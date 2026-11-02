"""Boundary tests for privileged approvals and fail-closed decisions."""

from datetime import UTC, datetime, timedelta

from sentinel_interlock.security.engine import evaluate_access
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


def make_policy(**overrides: object) -> AccessPolicy:
    values: dict[str, object] = {
        "policy_id": "approval-boundary-policy",
        "version": "1",
        "trusted_identity_issuers": frozenset({"https://id.example.test"}),
        "trusted_device_sources": frozenset({"edr.example.test"}),
        "required_authentication_methods": frozenset({"webauthn"}),
        "privileged_actions": frozenset({"secrets.read"}),
        "max_approval_age_seconds": 300,
    }
    values.update(overrides)
    return AccessPolicy(**values)


def make_request(**overrides: object) -> AccessRequest:
    values: dict[str, object] = {
        "identity": {
            "subject_id": "operator-1",
            "issuer": "https://id.example.test",
            "authenticated": True,
            "authentication_methods": frozenset({"webauthn"}),
            "authenticated_at": NOW,
        },
        "device": {
            "device_id": "workstation-1",
            "source_id": "edr.example.test",
            "posture": DevicePosture.HEALTHY,
            "observed_at": NOW,
        },
        "session": {
            "session_id": "session-1",
            "subject_id": "operator-1",
            "device_id": "workstation-1",
            "grants": frozenset(
                {SessionGrant(action="secrets.read", resource=RESOURCE)}
            ),
            "expires_at": NOW + timedelta(minutes=10),
        },
        "action": "secrets.read",
        "resource": RESOURCE,
        "approval": {
            "approver_subject_id": "approver-2",
            "action": "secrets.read",
            "resource": RESOURCE,
            "approved_at": NOW - timedelta(seconds=30),
            "expires_at": NOW + timedelta(minutes=2),
        },
    }
    values.update(overrides)
    return AccessRequest(**values)


def test_approval_at_maximum_age_boundary_is_accepted() -> None:
    request = make_request(
        approval={
            "approver_subject_id": "approver-2",
            "action": "secrets.read",
            "resource": RESOURCE,
            "approved_at": NOW - timedelta(seconds=300),
            "expires_at": NOW + timedelta(seconds=1),
        }
    )

    result = evaluate_access(request, make_policy(), now=NOW)

    assert result.decision is AccessDecision.ALLOW


def test_approval_older_than_maximum_age_is_denied() -> None:
    request = make_request(
        approval={
            "approver_subject_id": "approver-2",
            "action": "secrets.read",
            "resource": RESOURCE,
            "approved_at": NOW - timedelta(seconds=301),
            "expires_at": NOW + timedelta(minutes=1),
        }
    )

    result = evaluate_access(request, make_policy(), now=NOW)

    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.APPROVAL_EXPIRED in result.reason_codes


def test_future_approval_is_denied_with_distinct_reason() -> None:
    request = make_request(
        approval={
            "approver_subject_id": "approver-2",
            "action": "secrets.read",
            "resource": RESOURCE,
            "approved_at": NOW + timedelta(seconds=1),
            "expires_at": NOW + timedelta(minutes=1),
        }
    )

    result = evaluate_access(request, make_policy(), now=NOW)

    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.APPROVAL_NOT_YET_VALID in result.reason_codes
    assert AccessReasonCode.APPROVAL_EXPIRED not in result.reason_codes


def test_approval_expiring_at_evaluation_time_is_denied() -> None:
    request = make_request(
        approval={
            "approver_subject_id": "approver-2",
            "action": "secrets.read",
            "resource": RESOURCE,
            "approved_at": NOW - timedelta(seconds=1),
            "expires_at": NOW,
        }
    )

    result = evaluate_access(request, make_policy(), now=NOW)

    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.APPROVAL_EXPIRED in result.reason_codes


def test_approval_for_another_resource_is_denied() -> None:
    request = make_request(
        approval={
            "approver_subject_id": "approver-2",
            "action": "secrets.read",
            "resource": "vault://production/team-b",
            "approved_at": NOW - timedelta(seconds=10),
            "expires_at": NOW + timedelta(minutes=1),
        }
    )

    result = evaluate_access(request, make_policy(), now=NOW)

    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.APPROVAL_INVALID in result.reason_codes


def test_untrusted_device_evidence_cannot_override_explicit_denial() -> None:
    request = make_request(
        device={
            "device_id": "workstation-1",
            "source_id": "untrusted-edr",
            "posture": DevicePosture.HEALTHY,
            "observed_at": NOW,
        },
        approval=None,
    )

    result = evaluate_access(request, make_policy(), now=NOW)

    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.APPROVAL_REQUIRED in result.reason_codes
    assert AccessReasonCode.DEVICE_SOURCE_UNTRUSTED in result.reason_codes


def test_session_expiring_at_evaluation_time_is_denied() -> None:
    request = make_request(
        session={
            "session_id": "session-1",
            "subject_id": "operator-1",
            "device_id": "workstation-1",
            "grants": frozenset(
                {SessionGrant(action="secrets.read", resource=RESOURCE)}
            ),
            "expires_at": NOW,
        }
    )

    result = evaluate_access(request, make_policy(), now=NOW)

    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_EXPIRED in result.reason_codes
