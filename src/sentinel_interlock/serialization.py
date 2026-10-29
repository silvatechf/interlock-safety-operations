"""Versioned, deterministic serialization for decision evidence.

This format is suitable for fixtures and local demonstrations. It does not
provide signatures, tamper evidence, durable storage, or a trusted timestamp.
"""

from __future__ import annotations

import json
import math
from typing import Final

from pydantic import ValidationError

from .models import DecisionEvidence

EVIDENCE_SCHEMA_VERSION: Final[int] = 1
MAX_EVIDENCE_PAYLOAD_BYTES: Final[int] = 1_048_576


class EvidenceSerializationError(ValueError):
    """Raised when evidence JSON is malformed or uses an unsupported schema."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous JSON objects containing repeated property names."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceSerializationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> None:
    """Reject NaN and Infinity tokens, which are not valid JSON numbers."""
    raise EvidenceSerializationError(f"non-standard JSON constant: {value}")


def _validate_finite_numbers(value: object) -> None:
    """Reject non-finite floating-point values at any nesting depth."""
    if isinstance(value, float) and not math.isfinite(value):
        raise EvidenceSerializationError("evidence contains a non-finite number")
    if isinstance(value, dict):
        for child in value.values():
            _validate_finite_numbers(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_finite_numbers(child)


def serialize_evidence(decision: DecisionEvidence) -> str:
    """Serialize one decision using a versioned envelope and stable JSON ordering."""
    # Validate the original Python values: Pydantic's JSON-mode dump can normalize
    # non-finite floats (for example NaN) before json.dumps sees them.
    _validate_finite_numbers(decision.evidence)
    payload_data = decision.model_dump(mode="json")
    envelope = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "decision": payload_data,
    }
    try:
        payload = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceSerializationError("evidence cannot be represented as strict JSON") from exc
    if len(payload.encode("utf-8")) > MAX_EVIDENCE_PAYLOAD_BYTES:
        raise EvidenceSerializationError("serialized evidence exceeds the maximum payload size")
    return payload


def deserialize_evidence(payload: str) -> DecisionEvidence:
    """Validate a versioned evidence envelope; reject ambiguous or oversized JSON."""
    if not isinstance(payload, str):
        raise EvidenceSerializationError("evidence payload must be a string")
    try:
        payload_size = len(payload.encode("utf-8"))
    except UnicodeError as exc:
        raise EvidenceSerializationError("evidence payload is not valid UTF-8 text") from exc
    if payload_size > MAX_EVIDENCE_PAYLOAD_BYTES:
        raise EvidenceSerializationError("evidence payload exceeds the maximum payload size")
    try:
        envelope = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except EvidenceSerializationError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise EvidenceSerializationError("evidence payload is not valid JSON") from exc

    if not isinstance(envelope, dict):
        raise EvidenceSerializationError("evidence envelope must be a JSON object")

    version = envelope.get("schema_version")
    if version != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceSerializationError(f"unsupported evidence schema version: {version!r}")

    decision_data = envelope.get("decision")
    if not isinstance(decision_data, dict):
        raise EvidenceSerializationError("evidence decision must be a JSON object")

    try:
        _validate_finite_numbers(decision_data)
        return DecisionEvidence.model_validate(decision_data)
    except (EvidenceSerializationError, ValidationError, RecursionError) as exc:
        raise EvidenceSerializationError("evidence decision does not match the schema") from exc
