"""Ed25519 approval signature, key lifecycle, and secure consumption tests."""

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
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
        policy_id="replay-policy", version="1",
        trusted_identity_issuers=frozenset({"https://id.example.test"}),
        trusted_device_sources=frozenset({"edr.example.test"}),
        required_authentication_methods=frozenset({"webauthn"}),
        privileged_actions=frozenset({"secrets.read"}),
    )


def make_request() -> AccessRequest:
    request = AccessRequest(
        identity={
            "subject_id": "operator-1", "issuer": "https://id.example.test",
            "authenticated": True, "authentication_methods": frozenset({"webauthn"}),
            "authenticated_at": NOW,
        },
        device={
            "device_id": "workstation-1", "source_id": "edr.example.test",
            "posture": DevicePosture.HEALTHY, "observed_at": NOW,
        },
        session={
            "session_id": "session-1", "subject_id": "operator-1",
            "device_id": "workstation-1",
            "grants": frozenset({SessionGrant(action="secrets.read", resource=RESOURCE)}),
            "expires_at": NOW + timedelta(minutes=10),
        },
        action="secrets.read", resource=RESOURCE,
        approval={
            "approval_id": "approval-unique-001", "key_id": KEY_ID,
            "approver_subject_id": APPROVER, "action": "secrets.read",
            "resource": RESOURCE, "approved_at": NOW - timedelta(seconds=10),
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


def verifier_for(key: ApprovalVerificationKey, key_id: str = KEY_ID) -> Ed25519ApprovalVerifier:
    return Ed25519ApprovalVerifier({key_id: key})


def consume(request: AccessRequest, store: SQLiteApprovalStore, verifier=VERIFIER, now=NOW):
    return evaluate_and_consume_approval(
        request, make_policy(), store, approval_verifier=verifier, now=now
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
    result = consume(
        request.model_copy(update={"approval": altered}),
        SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
    )
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_unknown_key_fails_closed(tmp_path) -> None:
    request = make_request()
    assert request.approval is not None
    altered = request.approval.model_copy(update={"key_id": "unknown-key"})
    result = consume(
        request.model_copy(update={"approval": altered}),
        SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
    )
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_missing_signature_fails_closed(tmp_path) -> None:
    request = make_request()
    assert request.approval is not None
    altered = request.approval.model_copy(update={"signature": None})
    result = consume(
        request.model_copy(update={"approval": altered}),
        SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
    )
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_key_not_yet_active_is_rejected(tmp_path) -> None:
    key = ApprovalVerificationKey(
        APPROVER, PUBLIC_KEY, valid_from=NOW + timedelta(seconds=1)
    )
    result = consume(
        make_request(), SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
        verifier_for(key),
    )
    assert result.decision is AccessDecision.DENY
    assert result.reason_codes == (AccessReasonCode.APPROVAL_SIGNATURE_INVALID,)


def test_key_expiry_is_exclusive(tmp_path) -> None:
    key = ApprovalVerificationKey(
        APPROVER, PUBLIC_KEY, valid_until=NOW
    )
    result = consume(
        make_request(), SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
        verifier_for(key),
    )
    assert result.decision is AccessDecision.DENY


def test_revoked_key_is_rejected_at_and_after_revocation(tmp_path) -> None:
    key = ApprovalVerificationKey(
        APPROVER, PUBLIC_KEY, revoked_at=NOW
    )
    result = consume(
        make_request(), SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
        verifier_for(key),
    )
    assert result.decision is AccessDecision.DENY


def test_key_revocation_in_future_does_not_reject_before_boundary(tmp_path) -> None:
    key = ApprovalVerificationKey(
        APPROVER, PUBLIC_KEY, revoked_at=NOW + timedelta(seconds=1)
    )
    result = consume(
        make_request(), SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
        verifier_for(key),
    )
    assert result.decision is AccessDecision.ALLOW


def test_active_key_is_accepted(tmp_path) -> None:
    key = ApprovalVerificationKey(
        APPROVER, PUBLIC_KEY,
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
    )
    result = consume(
        make_request(), SQLiteApprovalStore(tmp_path / "approvals.sqlite3"),
        verifier_for(key),
    )
    assert result.decision is AccessDecision.ALLOW


def test_rotation_allows_old_and_new_keys_during_overlap(tmp_path) -> None:
    old_key = ApprovalVerificationKey(
        APPROVER, PUBLIC_KEY,
        valid_from=NOW - timedelta(days=10),
        valid_until=NOW + timedelta(days=1),
    )
    new_private = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    new_public = new_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_id = "approval-key-2026-02"
    new_approval = make_request().approval
    assert new_approval is not None
    new_approval = new_approval.model_copy(update={"key_id": new_id, "signature": None})
    new_signature = base64.urlsafe_b64encode(
        new_private.sign(approval_signing_payload(new_approval))
    ).rstrip(b"=").decode("ascii")
    new_approval = new_approval.model_copy(update={"signature": new_signature})
    new_verifier = Ed25519ApprovalVerifier({
        KEY_ID: old_key,
        new_id: ApprovalVerificationKey(
            APPROVER, new_public, valid_from=NOW - timedelta(seconds=1)
        ),
    })
    old_result = consume(
        make_request(), SQLiteApprovalStore(tmp_path / "old.sqlite3"), new_verifier
    )
    new_result = consume(
        make_request().model_copy(update={"approval": new_approval}),
        SQLiteApprovalStore(tmp_path / "new.sqlite3"), new_verifier,
    )
    assert old_result.decision is AccessDecision.ALLOW
    assert new_result.decision is AccessDecision.ALLOW


def test_invalid_key_configuration_is_rejected() -> None:
    with pytest.raises(ValueError):
        ApprovalVerificationKey(
            APPROVER, PUBLIC_KEY, valid_until=NOW - timedelta(seconds=1)
        )
    with pytest.raises(ValueError):
        ApprovalVerificationKey(APPROVER, PUBLIC_KEY, valid_from=NOW, valid_until=NOW)
    with pytest.raises(ValueError):
        ApprovalVerificationKey(
            APPROVER, PUBLIC_KEY, valid_from=datetime(2026, 1, 1)
        )


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
