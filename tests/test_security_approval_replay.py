"""Ed25519 approval signature and secure consumption tests."""

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_interlock.security.approval_signatures import (
    ApprovalVerificationKey,
    Ed25519ApprovalVerifier,
    approval_signing_payload,
)
from sentinel_interlock.security.approval_store import SQLiteApprovalStore
from sentinel_interlock.security.engine import evaluate_access, evaluate_and_consume_approval
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
KEY_ID = "approval-key-2026-01"
APPROVER = "approver-2"
# Deterministic test-only seed. Never use this key outside tests.
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
VERIFIER = Ed25519ApprovalVerifier(
    {KEY_ID: ApprovalVerificationKey(approver_subject_id=APPROVER, public_key=PUBLIC_KEY)}
)


def make_policy() -> AccessPolicy:
    return AccessPolicy(
        policy_id="replay-policy",
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
            "grants": frozenset({SessionGrant(action="secrets.read", resource=RESOURCE)}),
            "expires_at": NOW + timedelta(minutes=10),
        },
        action="secrets.read",
        resource=RESOURCE,
        approval={
            "approval_id": "approval-unique-001",
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
    signed_approval = request.approval.model_copy(update={"signature": signature})
    return request.model_copy(update={"approval": signed_approval})


def consume(request: AccessRequest, store: SQLiteApprovalStore):
    return evaluate_and_consume_approval(
        request, make_policy(), store, approval_verifier=VERIFIER, now=NOW
    )


def test_valid_signature_is_accepted_and_consumed_once(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    assert consume(make_request(), store).decision is AccessDecision.ALLOW
    replay = consume(make_request(), store)
    assert replay.decision is AccessDecision.DENY
    assert replay.reason_codes == (AccessReasonCode.APPROVAL_ALREADY_CONSUMED,)


def test_signature_survives_store_recreation(tmp_path) -> None:
    database = tmp_path / "approvals.sqlite3"
    first = consume(make_request(), SQLiteApprovalStore(database))
    replay = consume(make_request(), SQLiteApprovalStore(database))
    assert first.decision is AccessDecision.ALLOW
    assert replay.decision is AccessDecision.DENY


def test_tampered_approval_claim_fails_closed_without_consumption(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    request = make_request()
    assert request.approval is not None
    altered = request.approval.model_copy(update={"resource": "vault://production/team-b"})
    denied = consume(request.model_copy(update={"approval": altered}), store)
    valid = consume(request, store)
    assert denied.decision is AccessDecision.DENY
    assert denied.reason_codes == (AccessReasonCode.APPROVAL_INVALID,)
    assert valid.decision is AccessDecision.ALLOW


def test_tampered_approval_id_fails_signature_verification(tmp_path) -> None:
    request = make_request()
    assert request.approval is not None
    altered = request.approval.model_copy(update={"approval_id": "attacker-chosen-id"})
    result = consume(
        request.model_copy(update={"approval": altered}),
        SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
    )
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_tampered_approver_subject_fails_signature_verification(tmp_path) -> None:
    request = make_request()
    assert request.approval is not None
    altered = request.approval.model_copy(update={"approver_subject_id": "attacker"})
    result = consume(request.model_copy(update={"approval": altered}), SQLiteApprovalStore(
        tmp_path / "approvals.sqlite3"
    ))
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_unknown_key_fails_closed(tmp_path) -> None:
    request = make_request()
    assert request.approval is not None
    altered = request.approval.model_copy(update={"key_id": "unknown-key"})
    result = evaluate_and_consume_approval(
        request.model_copy(update={"approval": altered}),
        make_policy(),
        SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
        approval_verifier=VERIFIER,
        now=NOW,
    )
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_missing_signature_fails_closed(tmp_path) -> None:
    request = make_request()
    assert request.approval is not None
    altered = request.approval.model_copy(update={"signature": None})
    result = consume(request.model_copy(update={"approval": altered}), SQLiteApprovalStore(
        tmp_path / "approvals.sqlite3"
    ))
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_policy_denial_does_not_consume_valid_approval(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    request = make_request()
    compromised = request.device.model_copy(update={"posture": DevicePosture.COMPROMISED})
    denied = consume(request.model_copy(update={"device": compromised}), store)
    allowed = consume(request, store)
    assert denied.decision is AccessDecision.DENY
    assert allowed.decision is AccessDecision.ALLOW


def test_stateless_evaluator_remains_separate_from_signature_verification(tmp_path) -> None:
    request = make_request()
    assert evaluate_access(request, make_policy(), now=NOW).decision is AccessDecision.ALLOW
    result = consume(request, SQLiteApprovalStore(tmp_path / "approvals.sqlite3"))
    assert result.decision is AccessDecision.ALLOW


def test_concurrent_consumers_have_exactly_one_winner(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(lambda _: consume(make_request(), store), range(24)))
    assert sum(item.decision is AccessDecision.ALLOW for item in results) == 1
    assert sum(item.decision is AccessDecision.DENY for item in results) == 23
