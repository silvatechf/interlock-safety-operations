from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from sentinel_interlock.security.engine import evaluate_access
from sentinel_interlock.security.models import (
    AccessDecision,
    AccessPolicy,
    AccessReasonCode,
    AccessRequest,
    DevicePosture,
    IdentityAssertion,
    SessionGrant,
)

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
RESOURCE = "vault://production/team-a"


def make_policy(**overrides: object) -> AccessPolicy:
    values: dict[str, object] = {
        "policy_id": "workforce-privileged-access", "version": "1",
        "trusted_identity_issuers": frozenset({"https://id.example.test"}),
        "trusted_device_sources": frozenset({"edr.example.test"}),
        "required_authentication_methods": frozenset({"webauthn"}),
        "privileged_actions": frozenset({"secrets.read"}),
    }
    values.update(overrides)
    return AccessPolicy(**values)


def make_request(**overrides: object) -> AccessRequest:
    values: dict[str, object] = {
        "identity": {
            "subject_id": "operator-1", "issuer": "https://id.example.test",
            "authenticated": True, "authentication_methods": frozenset({"webauthn"}),
            "authenticated_at": NOW,
        },
        "device": {
            "device_id": "workstation-1", "source_id": "edr.example.test",
            "posture": DevicePosture.HEALTHY, "observed_at": NOW,
        },
        "session": {
            "session_id": "session-1", "subject_id": "operator-1",
            "device_id": "workstation-1",
            "grants": frozenset(
                {SessionGrant(action="secrets.read", resource=RESOURCE)}
            ),
            "expires_at": NOW + timedelta(minutes=10),
        },
        "action": "secrets.read", "resource": RESOURCE,
        "approval": {
            "approver_subject_id": "approver-2", "action": "secrets.read",
            "resource": RESOURCE, "approved_at": NOW - timedelta(seconds=10),
            "expires_at": NOW + timedelta(minutes=2),
        },
    }
    values.update(overrides)
    return AccessRequest(**values)


def test_healthy_independently_approved_access_is_allowed() -> None:
    result = evaluate_access(make_request(), make_policy(), now=NOW)
    assert result.decision is AccessDecision.ALLOW
    assert result.reason_codes == ()


def test_compromised_device_is_denied() -> None:
    device = make_request().device.model_copy(update={"posture": DevicePosture.COMPROMISED})
    result = evaluate_access(make_request(device=device), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.DEVICE_COMPROMISED in result.reason_codes


def test_untrusted_device_source_is_indeterminate() -> None:
    device = make_request().device.model_copy(update={"source_id": "unknown-edr"})
    result = evaluate_access(make_request(device=device), make_policy(), now=NOW)
    assert result.decision is AccessDecision.INDETERMINATE
    assert AccessReasonCode.DEVICE_SOURCE_UNTRUSTED in result.reason_codes


def test_stale_device_posture_is_indeterminate() -> None:
    device = make_request().device.model_copy(update={"observed_at": NOW - timedelta(minutes=5)})
    result = evaluate_access(make_request(device=device), make_policy(), now=NOW)
    assert result.decision is AccessDecision.INDETERMINATE
    assert AccessReasonCode.DEVICE_POSTURE_STALE in result.reason_codes


def test_missing_phishing_resistant_authentication_is_denied() -> None:
    identity = make_request().identity.model_copy(update={"authentication_methods": frozenset()})
    result = evaluate_access(make_request(identity=identity), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.AUTHENTICATION_METHOD_INSUFFICIENT in result.reason_codes


def test_revoked_session_is_denied() -> None:
    session = make_request().session.model_copy(update={"revoked": True})
    result = evaluate_access(make_request(session=session), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_REVOKED in result.reason_codes


def test_session_bound_to_another_subject_is_denied() -> None:
    session = make_request().session.model_copy(update={"subject_id": "operator-2"})
    result = evaluate_access(make_request(session=session), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_SUBJECT_MISMATCH in result.reason_codes


def test_session_bound_to_another_device_is_denied() -> None:
    session = make_request().session.model_copy(update={"device_id": "workstation-2"})
    result = evaluate_access(make_request(session=session), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_DEVICE_MISMATCH in result.reason_codes


def test_action_resource_pair_outside_session_grants_is_denied() -> None:
    session = make_request().session.model_copy(update={"grants": frozenset()})
    result = evaluate_access(make_request(session=session), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_SCOPE_INSUFFICIENT in result.reason_codes


def test_same_action_on_different_resource_is_denied() -> None:
    request = make_request(resource="vault://development/team-a")
    result = evaluate_access(request, make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_SCOPE_INSUFFICIENT in result.reason_codes


def test_privileged_action_requires_approval() -> None:
    result = evaluate_access(make_request(approval=None), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.APPROVAL_REQUIRED in result.reason_codes


def test_same_identity_cannot_approve_own_privileged_action() -> None:
    approval = make_request().approval.model_copy(update={"approver_subject_id": "operator-1"})
    result = evaluate_access(make_request(approval=approval), make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.APPROVER_NOT_INDEPENDENT in result.reason_codes


def test_unknown_device_posture_is_indeterminate() -> None:
    device = make_request().device.model_copy(update={"posture": DevicePosture.UNKNOWN})
    result = evaluate_access(make_request(device=device), make_policy(), now=NOW)
    assert result.decision is AccessDecision.INDETERMINATE
    assert AccessReasonCode.DEVICE_POSTURE_UNKNOWN in result.reason_codes


def test_naive_evaluation_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate_access(make_request(), make_policy(), now=datetime(2026, 10, 30, 12, 0))


def test_contracts_reject_unknown_fields_and_naive_timestamps() -> None:
    with pytest.raises(ValidationError):
        IdentityAssertion(
            subject_id="user", issuer="issuer", authenticated=True,
            authentication_methods=frozenset(),
            authenticated_at=datetime(2026, 10, 30, 12, 0), unexpected="field",
        )


def test_policy_fingerprint_is_stable_across_set_ordering() -> None:
    first = make_policy(
        trusted_identity_issuers=frozenset({"issuer-b", "issuer-a"}),
        trusted_device_sources=frozenset({"edr-b", "edr-a"}),
    )
    second = make_policy(
        trusted_identity_issuers=frozenset({"issuer-a", "issuer-b"}),
        trusted_device_sources=frozenset({"edr-a", "edr-b"}),
    )

    first_evidence = evaluate_access(make_request(), first, now=NOW)
    second_evidence = evaluate_access(make_request(), second, now=NOW)

    assert first_evidence.policy_sha256 == second_evidence.policy_sha256
    assert len(first_evidence.policy_sha256) == 64


def test_policy_fingerprint_changes_when_effective_configuration_changes() -> None:
    baseline = evaluate_access(make_request(), make_policy(), now=NOW)
    changed_policy = make_policy(max_device_posture_age_seconds=60)
    changed = evaluate_access(make_request(), changed_policy, now=NOW)

    assert baseline.policy_version == changed.policy_version
    assert baseline.policy_sha256 != changed.policy_sha256


def test_policy_fingerprint_is_validated_as_sha256_hex() -> None:
    evidence = evaluate_access(make_request(), make_policy(), now=NOW)
    with pytest.raises(ValidationError):
        evidence.model_copy(update={"policy_sha256": "not-a-digest"})
