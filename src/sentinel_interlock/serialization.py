"""Versioned, deterministic serialization for decision evidence.

This format is suitable for fixtures and local demonstrations. It does not
provide signatures, tamper evidence, durable storage, or a trusted timestamp.
"""

from __future__ import annotations

import json
from typing import Final

from pydantic import ValidationError

from .models import DecisionEvidence

EVIDENCE_SCHEMA_VERSION: Final[int] = 1


class EvidenceSerializationError(ValueError):
    """Raised when evidence JSON is malformed or uses an unsupported schema."""


def serialize_evidence(decision: DecisionEvidence) -> str:
    """Serialize one decision using a versioned envelope and stable JSON ordering."""
    envelope = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "decision": decision.model_dump(mode="json"),
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def deserialize_evidence(payload: str) -> DecisionEvidence:
    """Validate a versioned evidence envelope; reject unknown schema versions."""
    try:
        envelope = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise EvidenceSerializationError("evidence payload is not valid JSON") from exc

    if not isinstance(envelope, dict):
        raise EvidenceSerializationError("evidence envelope must be a JSON object")

    version = envelope.get("schema_version")
    if version != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceSerializationError(f"unsupported evidence schema version: {version!r}")

    decision = envelope.get("decision")
    if not isinstance(decision, dict):
        raise EvidenceSerializationError("evidence decision must be a JSON object")

    try:
        return DecisionEvidence.model_validate(decision)
    except ValidationError as exc:
        raise EvidenceSerializationError("evidence decision does not match the schema") from exc
