"""Process-local SHA-256 hash chain for serialized decision evidence.

This detects accidental or unsophisticated record edits when the expected chain
is retained. It is not a signature, authentication mechanism, trusted timestamp,
durable store, or protection against an attacker who can rewrite the whole chain.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass

from .models import DecisionEvidence
from .serialization import deserialize_evidence, serialize_evidence

CHAIN_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class EvidenceChainRecord:
    """One immutable record in a locally verifiable evidence sequence."""

    sequence: int
    previous_hash: str
    payload: str
    record_hash: str


def _record_hash(sequence: int, previous_hash: str, payload: str) -> str:
    """Hash a canonical representation of the record's committed fields."""
    canonical = json.dumps(
        {
            "chain_schema_version": CHAIN_SCHEMA_VERSION,
            "payload": payload,
            "previous_hash": previous_hash,
            "sequence": sequence,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class EvidenceChain:
    """Build and verify an in-memory hash chain of serialized decisions."""

    def __init__(self) -> None:
        self._records: list[EvidenceChainRecord] = []

    def append(self, decision: DecisionEvidence) -> EvidenceChainRecord:
        """Append a decision and return its hash-linked record."""
        sequence = len(self._records)
        previous_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
        payload = serialize_evidence(decision)
        record = EvidenceChainRecord(
            sequence=sequence,
            previous_hash=previous_hash,
            payload=payload,
            record_hash=_record_hash(sequence, previous_hash, payload),
        )
        self._records.append(record)
        return record

    def records(self) -> tuple[EvidenceChainRecord, ...]:
        """Return an immutable snapshot of the current chain."""
        return tuple(self._records)

    @staticmethod
    def verify(records: Iterable[EvidenceChainRecord]) -> bool:
        """Return whether records form a valid chain; malformed inputs fail closed."""
        try:
            iterator = iter(records)
        except TypeError:
            return False

        previous_hash = GENESIS_HASH
        for expected_sequence, record in enumerate(iterator):
            if not isinstance(record, EvidenceChainRecord):
                return False
            if (
                not isinstance(record.sequence, int)
                or isinstance(record.sequence, bool)
                or record.sequence != expected_sequence
                or not isinstance(record.previous_hash, str)
                or not isinstance(record.payload, str)
                or not isinstance(record.record_hash, str)
            ):
                return False
            if record.previous_hash != previous_hash:
                return False
            try:
                # Validate the evidence envelope as well as its committed bytes.
                deserialize_evidence(record.payload)
                expected_hash = _record_hash(
                    record.sequence, record.previous_hash, record.payload
                )
            except (TypeError, ValueError, UnicodeError, RecursionError):
                return False
            if record.record_hash != expected_hash:
                return False
            previous_hash = record.record_hash
        return True
