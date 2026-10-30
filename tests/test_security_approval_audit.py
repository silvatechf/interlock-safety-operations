"""Transactional audit coverage for signed privileged approvals."""

import base64
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_interlock.security.approval_audit import verify_audit_chain
from sentinel_interlock.security.approval_signatures import (
    ApprovalVerificationKey,
    Ed25519ApprovalVerifier,
    approval_signing_payload,
)
from sentinel_interlock.security.approval_store import SQLiteApprovalStore
from sentinel_interlock.security.engine import evaluate_and_consume_approval
from sentinel_interlock.security.models import (
    AccessDecision,
    AccessPolicy,
    AccessReasonCode,
    AccessRequest,
    DevicePosture,
    SessionGrant,
)

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
RESOURCE = "vault://production/team-a"
APPROVAL_ID = "approval-unique-001"
KEY_ID = "approval-key-2026-01"
APPROVER = "approver-2"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
VERIFIER = Ed25519ApprovalVerifier({
    KEY_ID: ApprovalVerificationKey(approver_subject_id=APPROVER, public_key=PUBLIC_KEY)
})


def make_policy() -> AccessPolicy:
    return AccessPolicy(
        policy_id="audit-policy",
        version="1",
        trusted_identity_issuers=frozenset({"https://id.example.test"}),
        trusted_device_sources=frozenset({"edr.example.test"}),
        required_authentication_methods=frozenset({"webauthn"}),
        privileged_actions=frozenset({"secrets.read"}),
    )


def make_request() -> AccessRequest:
    request = AccessRequest(
        identity={
            "subject_id": "operator-1",
            "issuer": "https://id.example.test",
            "authenticated": True,
            "authentication_methods": frozenset({"webauthn"}),
            "authenticated_at": NOW,
        },
        device={
            "device_id": "workstation-1",
            "source_id": "edr.example.test",
            "posture": DevicePosture.HEALTHY,
            "observed_at": NOW,
        },
        session={
            "session_id": "session-1",
            "subject_id": "operator-1",
            "device_id": "workstation-1",
            "grants": frozenset({
                SessionGrant(action="secrets.read", resource=RESOURCE)
            }),
            "expires_at": NOW + timedelta(minutes=10),
        },
        action="secrets.read",
        resource=RESOURCE,
        approval={
            "approval_id": APPROVAL_ID,
            "key_id": KEY_ID,
            "approver_subject_id": APPROVER,
            "action": "secrets.read",
            "resource": RESOURCE,
            "approved_at": NOW - timedelta(seconds=10),
            "expires_at": NOW + timedelta(minutes=2),
        },
    )
    assert request.approval is not None
    signature = base64.urlsafe_b64encode(
        PRIVATE_KEY.sign(approval_signing_payload(request.approval))
    ).rstrip(b"=").decode("ascii")
    return request.model_copy(update={
        "approval": request.approval.model_copy(update={"signature": signature})
    })


def consume(request: AccessRequest, store: SQLiteApprovalStore):
    return evaluate_and_consume_approval(
        request, make_policy(), store, approval_verifier=VERIFIER, now=NOW
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
    compromised = request.device.model_copy(update={"posture": DevicePosture.COMPROMISED})

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
    store = SQLiteApprovalStore(tmp_path / "audit.sqlite3")
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: consume(make_request(), store), range(16)))

    assert sum(item.decision is AccessDecision.ALLOW for item in results) == 1
    assert sum(item.decision is AccessDecision.DENY for item in results) == 15
    assert len(store.audit_records()) == 16
    assert store.verify_audit_chain()


def test_audit_failure_rolls_back_approval_consumption(tmp_path) -> None:
    database = tmp_path / "audit.sqlite3"
    store = SQLiteApprovalStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_audit BEFORE INSERT ON approval_decision_audit
            BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="audit unavailable"):
        consume(make_request(), store)

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER reject_audit")

    retried = consume(make_request(), store)
    assert retried.decision is AccessDecision.ALLOW
    assert len(store.audit_records()) == 1
    assert store.audit_records()[0].decision == "allow"
