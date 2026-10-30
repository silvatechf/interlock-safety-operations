"""Append-only hash-linked audit records for synthetic approval decisions.

The chain detects edits and reordering relative to a retained checkpoint. It is
not a digital signature, trusted timestamp, or protection against full database
rewrites by an attacker with write access.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable

from .models import AccessEvidence

AUDIT_CHAIN_SCHEMA_VERSION = 1
AUDIT_GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class ApprovalAuditRecord:
    """Minimized audit metadata for one evaluated approval decision."""

    sequence: int
    decision_id: str
    approval_id: str | None
    key_id: str | None
    decision: str
    reason_codes: tuple[str, ...]
    evaluated_at: str
    policy_sha256: str
    previous_hash: str
    record_hash: str


def _canonical_payload(
    *,
    sequence: int,
    decision_id: str,
    approval_id: str | None,
    key_id: str | None,
    decision: str,
    reason_codes: tuple[str, ...],
    evaluated_at: str,
    policy_sha256: str,
    previous_hash: str,
) -> bytes:
    return json.dumps(
        {
            "schema_version": AUDIT_CHAIN_SCHEMA_VERSION,
            "sequence": sequence,
            "decision_id": decision_id,
            "approval_id": approval_id,
            "key_id": key_id,
            "decision": decision,
            "reason_codes": list(reason_codes),
            "evaluated_at": evaluated_at,
            "policy_sha256": policy_sha256,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def create_audit_record(
    evidence: AccessEvidence,
    *,
    sequence: int,
    approval_id: str | None,
    key_id: str | None,
    previous_hash: str,
) -> ApprovalAuditRecord:
    """Create a hash-linked record without copying resource or identity claims."""
    reason_codes = tuple(reason.value for reason in evidence.reason_codes)
    evaluated_at = evidence.evaluated_at.isoformat()
    payload = _canonical_payload(
        sequence=sequence,
        decision_id=evidence.decision_id,
        approval_id=approval_id,
        key_id=key_id,
        decision=evidence.decision.value,
        reason_codes=reason_codes,
        evaluated_at=evaluated_at,
        policy_sha256=evidence.policy_sha256,
        previous_hash=previous_hash,
    )
    return ApprovalAuditRecord(
        sequence=sequence,
        decision_id=evidence.decision_id,
        approval_id=approval_id,
        key_id=key_id,
        decision=evidence.decision.value,
        reason_codes=reason_codes,
        evaluated_at=evaluated_at,
        policy_sha256=evidence.policy_sha256,
        previous_hash=previous_hash,
        record_hash=hashlib.sha256(payload).hexdigest(),
    )


def verify_audit_chain(records: Iterable[ApprovalAuditRecord]) -> bool:
    """Verify sequence, linkage, and record hashes; malformed input fails closed."""
    try:
        iterator = iter(records)
    except TypeError:
        return False

    previous_hash = AUDIT_GENESIS_HASH
    for expected_sequence, record in enumerate(iterator):
        if not isinstance(record, ApprovalAuditRecord):
            return False
        if type(record.sequence) is not int or record.sequence != expected_sequence:
            return False
        if record.previous_hash != previous_hash:
            return False
        try:
            payload = _canonical_payload(
                sequence=record.sequence,
                decision_id=record.decision_id,
                approval_id=record.approval_id,
                key_id=record.key_id,
                decision=record.decision,
                reason_codes=record.reason_codes,
                evaluated_at=record.evaluated_at,
                policy_sha256=record.policy_sha256,
                previous_hash=record.previous_hash,
            )
            expected_hash = hashlib.sha256(payload).hexdigest()
        except (TypeError, ValueError, AttributeError):
            return False
        if expected_hash != record.record_hash:
            return False
        previous_hash = record.record_hash
    return True
