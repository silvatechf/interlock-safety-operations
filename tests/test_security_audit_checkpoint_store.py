"""Local file persistence tests for approval-audit checkpoints."""

import json

import pytest

from sentinel_interlock.security.approval_audit import ApprovalAuditCheckpoint
from sentinel_interlock.security.audit_checkpoint_store import (
    JsonFileApprovalAuditCheckpointStore,
)


def make_checkpoint() -> ApprovalAuditCheckpoint:
    return ApprovalAuditCheckpoint(
        schema_version=1,
        sequence=7,
        record_hash="a" * 64,
    )


def test_missing_checkpoint_returns_none(tmp_path) -> None:
    store = JsonFileApprovalAuditCheckpointStore(tmp_path / "checkpoint.json")

    assert store.load() is None


def test_checkpoint_round_trip_uses_strict_json(tmp_path) -> None:
    path = tmp_path / "checkpoint.json"
    store = JsonFileApprovalAuditCheckpointStore(path)
    checkpoint = make_checkpoint()

    store.save(checkpoint)

    assert store.load() == checkpoint
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "sequence": 7,
        "record_hash": "a" * 64,
    }


def test_save_rejects_invalid_checkpoint_values(tmp_path) -> None:
    store = JsonFileApprovalAuditCheckpointStore(tmp_path / "checkpoint.json")

    with pytest.raises(ValueError, match="sequence"):
        store.save(ApprovalAuditCheckpoint(1, -1, "a" * 64))
    with pytest.raises(ValueError, match="record_hash"):
        store.save(ApprovalAuditCheckpoint(1, 0, "not-a-hash"))
    with pytest.raises(ValueError, match="schema_version"):
        store.save(ApprovalAuditCheckpoint(2, 0, "a" * 64))


@pytest.mark.parametrize(
    "content",
    [
        "{",
        "[]",
        '{"schema_version":1,"sequence":0,"record_hash":"' + "a" * 64 + '","extra":true}',
        '{"schema_version":true,"sequence":0,"record_hash":"' + "a" * 64 + '"}',
        '{"schema_version":1,"sequence":-1,"record_hash":"' + "a" * 64 + '"}',
    ],
)
def test_load_rejects_malformed_or_invalid_checkpoint_files(tmp_path, content: str) -> None:
    path = tmp_path / "checkpoint.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        JsonFileApprovalAuditCheckpointStore(path).load()


def test_save_requires_existing_parent_directory(tmp_path) -> None:
    path = tmp_path / "missing" / "checkpoint.json"
    store = JsonFileApprovalAuditCheckpointStore(path)

    with pytest.raises(FileNotFoundError):
        store.save(make_checkpoint())


def make_audit_record():
    import hashlib

    from sentinel_interlock.security.approval_audit import (
        AUDIT_CHAIN_SCHEMA_VERSION,
        AUDIT_GENESIS_HASH,
        ApprovalAuditRecord,
    )

    values = {
        "schema_version": AUDIT_CHAIN_SCHEMA_VERSION,
        "sequence": 0,
        "decision_id": "decision-1",
        "approval_id": None,
        "key_id": None,
        "decision": "deny",
        "reason_codes": ["policy_denied"],
        "evaluated_at": "2026-01-01T00:00:00+00:00",
        "policy_sha256": "b" * 64,
        "previous_hash": AUDIT_GENESIS_HASH,
    }
    payload = json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return ApprovalAuditRecord(
        sequence=0,
        decision_id="decision-1",
        approval_id=None,
        key_id=None,
        decision="deny",
        reason_codes=("policy_denied",),
        evaluated_at="2026-01-01T00:00:00+00:00",
        policy_sha256="b" * 64,
        previous_hash=AUDIT_GENESIS_HASH,
        record_hash=hashlib.sha256(payload).hexdigest(),
    )


def test_verification_reports_missing_checkpoint(tmp_path) -> None:
    from sentinel_interlock.security.audit_checkpoint_store import (
        AuditCheckpointStatus,
        verify_stored_audit_checkpoint,
    )

    store = JsonFileApprovalAuditCheckpointStore(tmp_path / "checkpoint.json")

    assert verify_stored_audit_checkpoint((make_audit_record(),), store) is (
        AuditCheckpointStatus.MISSING
    )


def test_verification_accepts_matching_checkpoint(tmp_path) -> None:
    from sentinel_interlock.security.audit_checkpoint_store import (
        AuditCheckpointStatus,
        verify_stored_audit_checkpoint,
    )

    record = make_audit_record()
    checkpoint = ApprovalAuditCheckpoint(1, 0, record.record_hash)
    store = JsonFileApprovalAuditCheckpointStore(tmp_path / "checkpoint.json")
    store.save(checkpoint)

    assert verify_stored_audit_checkpoint((record,), store) is AuditCheckpointStatus.VALID


def test_verification_rejects_mismatched_checkpoint(tmp_path) -> None:
    from sentinel_interlock.security.audit_checkpoint_store import (
        AuditCheckpointStatus,
        verify_stored_audit_checkpoint,
    )

    record = make_audit_record()
    store = JsonFileApprovalAuditCheckpointStore(tmp_path / "checkpoint.json")
    store.save(ApprovalAuditCheckpoint(1, 0, "c" * 64))

    assert verify_stored_audit_checkpoint((record,), store) is AuditCheckpointStatus.INVALID
