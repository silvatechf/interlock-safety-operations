"""Property-based authorization invariants."""

from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

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


def make_policy() -> AccessPolicy:
    return AccessPolicy(
        policy_id="property-test-policy",
        version="1",
        trusted_identity_issuers=frozenset({"https://id.example.test"}),
        trusted_device_sources=frozenset({"edr.example.test"}),
        required_authentication_methods=frozenset({"webauthn"}),
        privileged_actions=frozenset({"secrets.read"}),
    )


def make_request() -> AccessRequest:
    return AccessRequest(
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
        resource="vault://production/team-a",
        approval={
            "approver_subject_id": "approver-2",
            "action": "secrets.read",
            "resource": RESOURCE,
            "approved_at": NOW - timedelta(seconds=10),
            "expires_at": NOW + timedelta(minutes=2),
        },
    )


@given(revoked=st.booleans())
def test_revoked_session_never_allows(revoked: bool) -> None:
    request = make_request()
    session = request.session.model_copy(update={"revoked": revoked})
    result = evaluate_access(
        request.model_copy(update={"session": session}), make_policy(), now=NOW
    )
    if revoked:
        assert result.decision is AccessDecision.DENY
        assert AccessReasonCode.SESSION_REVOKED in result.reason_codes
    else:
        assert result.decision is AccessDecision.ALLOW


@given(posture=st.sampled_from([DevicePosture.COMPROMISED, DevicePosture.UNKNOWN]))
def test_non_healthy_device_never_allows(posture: DevicePosture) -> None:
    request = make_request()
    device = request.device.model_copy(update={"posture": posture})
    result = evaluate_access(
        request.model_copy(update={"device": device}), make_policy(), now=NOW
    )
    assert result.decision is not AccessDecision.ALLOW
    expected = (
        AccessReasonCode.DEVICE_COMPROMISED
        if posture is DevicePosture.COMPROMISED
        else AccessReasonCode.DEVICE_POSTURE_UNKNOWN
    )
    assert expected in result.reason_codes


@given(age=st.integers(min_value=121, max_value=86400))
def test_stale_device_evidence_never_allows(age: int) -> None:
    request = make_request()
    device = request.device.model_copy(
        update={"observed_at": NOW - timedelta(seconds=age)}
    )
    result = evaluate_access(
        request.model_copy(update={"device": device}), make_policy(), now=NOW
    )
    assert result.decision is AccessDecision.INDETERMINATE
    assert AccessReasonCode.DEVICE_POSTURE_STALE in result.reason_codes


@given(age=st.integers(min_value=301, max_value=86400))
def test_stale_identity_evidence_never_allows(age: int) -> None:
    request = make_request()
    identity = request.identity.model_copy(
        update={"authenticated_at": NOW - timedelta(seconds=age)}
    )
    result = evaluate_access(
        request.model_copy(update={"identity": identity}), make_policy(), now=NOW
    )
    assert result.decision is AccessDecision.INDETERMINATE
    assert AccessReasonCode.IDENTITY_ASSERTION_STALE in result.reason_codes


@given(subject_id=st.text(min_size=1, max_size=128).filter(lambda value: value != "operator-1"))
def test_session_subject_mismatch_never_allows(subject_id: str) -> None:
    request = make_request()
    session = request.session.model_copy(update={"subject_id": subject_id})
    result = evaluate_access(
        request.model_copy(update={"session": session}), make_policy(), now=NOW
    )
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_SUBJECT_MISMATCH in result.reason_codes


@given(device_id=st.text(min_size=1, max_size=128).filter(lambda value: value != "workstation-1"))
def test_session_device_mismatch_never_allows(device_id: str) -> None:
    request = make_request()
    session = request.session.model_copy(update={"device_id": device_id})
    result = evaluate_access(
        request.model_copy(update={"session": session}), make_policy(), now=NOW
    )
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_DEVICE_MISMATCH in result.reason_codes


@given(scope_present=st.booleans())
def test_privileged_action_requires_exact_session_grant(scope_present: bool) -> None:
    request = make_request()
    grants = frozenset({SessionGrant(action="secrets.read", resource=RESOURCE)}) if scope_present else frozenset()
    session = request.session.model_copy(update={"grants": grants})
    result = evaluate_access(
        request.model_copy(update={"session": session}), make_policy(), now=NOW
    )
    if scope_present:
        assert result.decision is AccessDecision.ALLOW
    else:
        assert result.decision is AccessDecision.DENY
        assert AccessReasonCode.SESSION_SCOPE_INSUFFICIENT in result.reason_codes


@given(resource=st.text(min_size=1, max_size=256).filter(lambda value: value != RESOURCE))
def test_same_action_on_ungranted_resource_never_allows(resource: str) -> None:
    request = make_request().model_copy(update={"resource": resource})
    result = evaluate_access(request, make_policy(), now=NOW)
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.SESSION_SCOPE_INSUFFICIENT in result.reason_codes


@given(action=st.sampled_from(["secrets.read", "secrets.write", "users.delete"]))
def test_privileged_approval_must_match_requested_action(action: str) -> None:
    request = make_request()
    approval = request.approval.model_copy(update={"action": action})
    result = evaluate_access(
        request.model_copy(update={"approval": approval}), make_policy(), now=NOW
    )
    if action == "secrets.read":
        assert result.decision is AccessDecision.ALLOW
    else:
        assert result.decision is AccessDecision.DENY
        assert AccessReasonCode.APPROVAL_INVALID in result.reason_codes


@given(
    issuer=st.text(min_size=1, max_size=40).filter(
        lambda value: value != "https://id.example.test"
    )
)
def test_untrusted_identity_issuer_never_allows(issuer: str) -> None:
    request = make_request()
    identity = request.identity.model_copy(update={"issuer": issuer})
    result = evaluate_access(
        request.model_copy(update={"identity": identity}), make_policy(), now=NOW
    )
    assert result.decision is AccessDecision.INDETERMINATE
    assert AccessReasonCode.IDENTITY_ISSUER_UNTRUSTED in result.reason_codes
