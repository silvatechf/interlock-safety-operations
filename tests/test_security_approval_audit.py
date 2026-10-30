"""Transactional audit coverage for signed privileged approvals."""

from dataclasses import replace

from sentinel_interlock.security.approval_audit import verify_audit_chain
from sentinel_interlock.security.models import AccessDecision, AccessReasonCode

from test_security_approval_replay import (
    NOW,
    SQLiteApprovalStore,
    VERIFIER,
    consume,
    make_request,
)


def test_allow_and_replay_deny_are_both_audited(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")

    allowed = consume(make_request(), store)
    denied = consume(make_request(), store)
    records = store.audit_records()

    assert allowed.decision is AccessDecision.ALLOW
    assert denied.decision is AccessDecision.DENY
    assert len(records) == 2
    assert records[0].decision == "allow"
    assert records[0].reason_codes == ()
    assert records[1].decision == "deny"
    assert records[1].reason_codes == (AccessReasonCode.APPROVAL_ALREADY_CONSUMED.value,)
    assert all(item.approval_id == "approval-unique-001" for item in records)
    assert all(item.key_id == "approval-key-2026-01" for item in records)
    assert store.verify_audit_chain()


def test_policy_denial_is_audited_without_consuming_approval(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")
    request = make_request()
    compromised = request.device.model_copy(update={"posture": "compromised"})

    result = consume(request.model_copy(update={"device": compromised}), store)
    next_result = consume(request, store)

    records = store.audit_records()
    assert result.decision is AccessDecision.DENY
    assert records[0].reason_codes == (AccessReasonCode.DEVICE_COMPROMISED.value,)
    assert next_result.decision is AccessDecision.ALLOW
    assert len(records) == 2


def test_invalid_signature_is_audited_without_consumption(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")
    request = make_request()
    altered = request.approval.model_copy(update={"signature": "invalid"})
    result = consume(request.model_copy(update={"approval": altered}), store)

    assert result.decision is AccessDecision.DENY
    record = store.audit_records()[0]
    assert record.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID.value,)
    assert record.key_id == "approval-key-2026-01"


def test_audit_chain_detects_record_tampering(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")
    consume(make_request(), store)
    records = store.audit_records()

    tampered = (replace(records[0], decision="deny"),)
    assert not verify_audit_chain(tampered)
    assert store.verify_audit_chain()


def test_audit_chain_detects_reordering_and_truncation_of_middle_record(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")
    for _ in range(3):
        consume(make_request(), store)
    records = store.audit_records()

    assert not verify_audit_chain((records[1], records[0], records[2]))
    assert not verify_audit_chain((records[0], records[2]))


def test_audit_record_minimizes_identity_and_resource_data(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")
    consume(make_request(), store)
    record = store.audit_records()[0]

    assert not hasattr(record, "subject_id")
    assert not hasattr(record, "resource")
    assert record.evaluated_at == NOW.isoformat()


def test_concurrent_replay_attempts_produce_one_allow_and_audit_every_result(tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: consume(make_request(), store), range(16)))

    assert sum(item.decision is AccessDecision.ALLOW for item in results) == 1
    assert sum(item.decision is AccessDecision.DENY for item in results) == 15
    assert len(store.audit_records()) == 16
    assert store.verify_audit_chain()
