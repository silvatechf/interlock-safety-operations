"""Deterministic access decision evaluation; no authentication or enforcement."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from .approval_store import ApprovalStore
from .models import (
    AccessDecision,
    AccessEvidence,
    AccessPolicy,
    AccessReasonCode,
    AccessRequest,
    DevicePosture,
    SessionGrant,
)


def _policy_fingerprint(policy: AccessPolicy) -> str:
    """Return a stable SHA-256 fingerprint of the effective policy configuration."""
    canonical_policy = {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "trusted_identity_issuers": sorted(policy.trusted_identity_issuers),
        "trusted_device_sources": sorted(policy.trusted_device_sources),
        "required_authentication_methods": sorted(policy.required_authentication_methods),
        "privileged_actions": sorted(policy.privileged_actions),
        "max_identity_age_seconds": policy.max_identity_age_seconds,
        "max_device_posture_age_seconds": policy.max_device_posture_age_seconds,
        "max_approval_age_seconds": policy.max_approval_age_seconds,
    }
    encoded = json.dumps(
        canonical_policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evaluate_access(
    request: AccessRequest,
    policy: AccessPolicy,
    *,
    now: datetime | None = None,
) -> AccessEvidence:
    """Evaluate synthetic identity, device, session, and approval assertions."""
    evaluated_at = now or datetime.now(UTC)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    denied: list[AccessReasonCode] = []
    indeterminate: list[AccessReasonCode] = []
    identity, device, session = request.identity, request.device, request.session

    if not identity.authenticated:
        denied.append(AccessReasonCode.IDENTITY_NOT_AUTHENTICATED)
    if identity.issuer not in policy.trusted_identity_issuers:
        indeterminate.append(AccessReasonCode.IDENTITY_ISSUER_UNTRUSTED)
    identity_age = (evaluated_at - identity.authenticated_at).total_seconds()
    if identity_age < 0 or identity_age > policy.max_identity_age_seconds:
        indeterminate.append(AccessReasonCode.IDENTITY_ASSERTION_STALE)
    if not policy.required_authentication_methods.issubset(
        identity.authentication_methods
    ):
        denied.append(AccessReasonCode.AUTHENTICATION_METHOD_INSUFFICIENT)

    if device.source_id not in policy.trusted_device_sources:
        indeterminate.append(AccessReasonCode.DEVICE_SOURCE_UNTRUSTED)
    device_age = (evaluated_at - device.observed_at).total_seconds()
    if device_age < 0 or device_age > policy.max_device_posture_age_seconds:
        indeterminate.append(AccessReasonCode.DEVICE_POSTURE_STALE)
    if device.posture is DevicePosture.COMPROMISED:
        denied.append(AccessReasonCode.DEVICE_COMPROMISED)
    elif device.posture is DevicePosture.UNKNOWN:
        indeterminate.append(AccessReasonCode.DEVICE_POSTURE_UNKNOWN)

    if session.subject_id != identity.subject_id:
        denied.append(AccessReasonCode.SESSION_SUBJECT_MISMATCH)
    if session.device_id != device.device_id:
        denied.append(AccessReasonCode.SESSION_DEVICE_MISMATCH)
    if session.revoked:
        denied.append(AccessReasonCode.SESSION_REVOKED)
    if evaluated_at >= session.expires_at:
        denied.append(AccessReasonCode.SESSION_EXPIRED)
    requested_grant = SessionGrant(action=request.action, resource=request.resource)
    if requested_grant not in session.grants:
        denied.append(AccessReasonCode.SESSION_SCOPE_INSUFFICIENT)

    if request.action in policy.privileged_actions:
        approval = request.approval
        if approval is None:
            denied.append(AccessReasonCode.APPROVAL_REQUIRED)
        else:
            if approval.approver_subject_id == identity.subject_id:
                denied.append(AccessReasonCode.APPROVER_NOT_INDEPENDENT)
            if approval.action != request.action or approval.resource != request.resource:
                denied.append(AccessReasonCode.APPROVAL_INVALID)
            if approval.approved_at > evaluated_at:
                denied.append(AccessReasonCode.APPROVAL_NOT_YET_VALID)
            else:
                approval_age = (evaluated_at - approval.approved_at).total_seconds()
                if (
                    approval_age > policy.max_approval_age_seconds
                    or evaluated_at >= approval.expires_at
                ):
                    denied.append(AccessReasonCode.APPROVAL_EXPIRED)

    unique_denied = tuple(dict.fromkeys(denied))
    unique_indeterminate = tuple(dict.fromkeys(indeterminate))
    if unique_denied:
        decision = AccessDecision.DENY
        reasons = unique_denied + unique_indeterminate
    elif unique_indeterminate:
        decision = AccessDecision.INDETERMINATE
        reasons = unique_indeterminate
    else:
        decision, reasons = AccessDecision.ALLOW, ()

    return AccessEvidence(
        decision_id=str(uuid4()),
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_sha256=_policy_fingerprint(policy),
        decision=decision,
        reason_codes=reasons,
        evaluated_at=evaluated_at,
        subject_id=identity.subject_id,
        device_id=device.device_id,
        session_id=session.session_id,
        action=request.action,
        resource=request.resource,
    )


def evaluate_and_consume_approval(
    request: AccessRequest,
    policy: AccessPolicy,
    approval_store: ApprovalStore,
    *,
    now: datetime | None = None,
) -> AccessEvidence:
    """Evaluate policy and atomically consume approval only after an ALLOW."""
    evidence = evaluate_access(request, policy, now=now)
    if (
        evidence.decision is not AccessDecision.ALLOW
        or request.action not in policy.privileged_actions
        or request.approval is None
    ):
        return evidence

    consumed = approval_store.consume(
        request.approval.approval_id,
        consumed_at=evidence.evaluated_at,
        decision_id=evidence.decision_id,
    )
    if consumed:
        return evidence
    return evidence.model_copy(
        update={
            "decision": AccessDecision.DENY,
            "reason_codes": (AccessReasonCode.APPROVAL_ALREADY_CONSUMED,),
        }
    )
