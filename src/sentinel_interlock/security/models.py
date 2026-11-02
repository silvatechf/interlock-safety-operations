"""Strict contracts for synthetic privileged-access evaluations."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


class DevicePosture(StrEnum):
    HEALTHY = "healthy"
    COMPROMISED = "compromised"
    UNKNOWN = "unknown"


class AccessDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


class AccessReasonCode(StrEnum):
    IDENTITY_NOT_AUTHENTICATED = "identity_not_authenticated"
    IDENTITY_ISSUER_UNTRUSTED = "identity_issuer_untrusted"
    IDENTITY_ASSERTION_STALE = "identity_assertion_stale"
    AUTHENTICATION_METHOD_INSUFFICIENT = "authentication_method_insufficient"
    DEVICE_SOURCE_UNTRUSTED = "device_source_untrusted"
    DEVICE_POSTURE_UNKNOWN = "device_posture_unknown"
    DEVICE_COMPROMISED = "device_compromised"
    DEVICE_POSTURE_STALE = "device_posture_stale"
    SESSION_REVOKED = "session_revoked"
    SESSION_EXPIRED = "session_expired"
    SESSION_SCOPE_INSUFFICIENT = "session_scope_insufficient"
    SESSION_SUBJECT_MISMATCH = "session_subject_mismatch"
    SESSION_DEVICE_MISMATCH = "session_device_mismatch"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_NOT_YET_VALID = "approval_not_yet_valid"
    APPROVAL_ALREADY_CONSUMED = "approval_already_consumed"
    APPROVER_NOT_INDEPENDENT = "approver_not_independent"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IdentityAssertion(_StrictModel):
    subject_id: str = Field(min_length=1, max_length=128)
    issuer: str = Field(min_length=1, max_length=256)
    authenticated: bool
    authentication_methods: frozenset[str] = frozenset()
    authenticated_at: datetime

    @field_validator("authenticated_at")
    @classmethod
    def validate_authenticated_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class DeviceAssertion(_StrictModel):
    device_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=128)
    posture: DevicePosture
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class SessionGrant(_StrictModel):
    """Exact action/resource permission carried by a synthetic session."""

    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=256)


class SessionAssertion(_StrictModel):
    session_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    grants: frozenset[SessionGrant] = frozenset()
    expires_at: datetime
    revoked: bool = False

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class ApprovalAssertion(_StrictModel):
    approval_id: str = Field(min_length=1, max_length=128)
    approver_subject_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=256)
    approved_at: datetime
    expires_at: datetime

    @field_validator("approved_at", "expires_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @model_validator(mode="after")
    def validate_window(self) -> ApprovalAssertion:
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expiry must be after approval time")
        return self


class AccessRequest(_StrictModel):
    identity: IdentityAssertion
    device: DeviceAssertion
    session: SessionAssertion
    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=256)
    approval: ApprovalAssertion | None = None


class AccessPolicy(_StrictModel):
    policy_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    trusted_identity_issuers: frozenset[str]
    trusted_device_sources: frozenset[str]
    required_authentication_methods: frozenset[str] = frozenset()
    privileged_actions: frozenset[str] = frozenset()
    max_identity_age_seconds: int = Field(default=300, ge=0, le=86400)
    max_device_posture_age_seconds: int = Field(default=120, ge=0, le=86400)
    max_approval_age_seconds: int = Field(default=300, ge=1, le=86400)

    @field_validator(
        "trusted_identity_issuers", "trusted_device_sources",
        "required_authentication_methods", "privileged_actions",
    )
    @classmethod
    def reject_blank_entries(cls, values: frozenset[str]) -> frozenset[str]:
        if any(not value.strip() for value in values):
            raise ValueError("policy entries must not be blank")
        return values


class AccessEvidence(_StrictModel):
    decision_id: str = Field(min_length=1, max_length=64)
    policy_id: str
    policy_version: str
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: AccessDecision
    reason_codes: tuple[AccessReasonCode, ...]
    evaluated_at: datetime
    subject_id: str
    device_id: str
    session_id: str
    action: str
    resource: str

    @field_validator("evaluated_at")
    @classmethod
    def validate_evaluated_at(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @model_validator(mode="after")
    def validate_decision_reasons(self) -> AccessEvidence:
        if self.decision is AccessDecision.ALLOW and self.reason_codes:
            raise ValueError("ALLOW must not contain reason codes")
        if self.decision is not AccessDecision.ALLOW and not self.reason_codes:
            raise ValueError("DENY and INDETERMINATE require reason codes")
        return self
