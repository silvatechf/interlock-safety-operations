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
