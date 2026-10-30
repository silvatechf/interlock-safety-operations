"""Durable and concurrent approval-consumption tests."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from sentinel_interlock.security.approval_store import SQLiteApprovalStore
from sentinel_interlock.security.engine import evaluate_access, evaluate_and_consume_approval
from sentinel_interlock.security.models import (
    AccessDecision, AccessPolicy, AccessReasonCode, AccessRequest, DevicePosture, SessionGrant,
)

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
RESOURCE = "vault://production/team-a"


def make_policy() -> AccessPolicy:
    return AccessPolicy(
        policy_id="replay-policy", version="1",
        trusted_identity_issuers=frozenset({"https://id.example.test"}),
        trusted_device_sources=frozenset({"edr.example.test"}),
        required_authentication_methods=frozenset({"webauthn"}),
        privileged_actions=frozenset({"secrets.read"}),
    )


def make_request() -> AccessRequest:
    return AccessRequest(
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
            "approval_id": "approval-unique-001", "approver_subject_id": "approver-2",
            "action": "secrets.read", "resource": RESOURCE,
            "approved_at": NOW - timedelta(seconds=10),
            "expires_at": NOW + timedelta(minutes=2),
        },
    )


def test_approval_is_consumed_once_and_replay_is_denied(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    first = evaluate_and_consume_approval(make_request(), make_policy(), store, now=NOW)
    replay = evaluate_and_consume_approval(make_request(), make_policy(), store, now=NOW)
    assert first.decision is AccessDecision.ALLOW
    assert replay.decision is AccessDecision.DENY
    assert replay.reason_codes == (AccessReasonCode.APPROVAL_ALREADY_CONSUMED,)


def test_consumption_survives_store_recreation(tmp_path) -> None:
    database = tmp_path / "approvals.sqlite3"
    first = evaluate_and_consume_approval(
        make_request(), make_policy(), SQLiteApprovalStore(database), now=NOW
    )
    replay = evaluate_and_consume_approval(
        make_request(), make_policy(), SQLiteApprovalStore(database), now=NOW
    )
    assert first.decision is AccessDecision.ALLOW
    assert replay.decision is AccessDecision.DENY


def test_policy_denial_does_not_consume_approval(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    request = make_request()
    compromised = request.device.model_copy(update={"posture": DevicePosture.COMPROMISED})
    denied = evaluate_and_consume_approval(
        request.model_copy(update={"device": compromised}), make_policy(), store, now=NOW
    )
    allowed = evaluate_and_consume_approval(request, make_policy(), store, now=NOW)
    assert denied.decision is AccessDecision.DENY
    assert allowed.decision is AccessDecision.ALLOW


def test_stateless_evaluator_does_not_consume_approval(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    assert evaluate_access(make_request(), make_policy(), now=NOW).decision is AccessDecision.ALLOW
    assert evaluate_and_consume_approval(
        make_request(), make_policy(), store, now=NOW
    ).decision is AccessDecision.ALLOW


def test_concurrent_consumers_have_exactly_one_winner(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.sqlite3")
    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(
            lambda _: evaluate_and_consume_approval(
                make_request(), make_policy(), store, now=NOW
            ),
            range(24),
        ))
    assert sum(item.decision is AccessDecision.ALLOW for item in results) == 1
    assert sum(item.decision is AccessDecision.DENY for item in results) == 23
