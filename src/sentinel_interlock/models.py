"""Validated domain-neutral request, policy, context, and decision models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DecisionStatus(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ReasonCode(StrEnum):
    AUTHENTICATION_REQUIRED = "authentication_required"
    ACTOR_NOT_AUTHORIZED = "actor_not_authorized"
    COMMAND_NOT_ALLOWED = "command_not_allowed"
    CONTEXT_MISSING = "context_missing"
    CONTEXT_STALE = "context_stale"
    CONTEXT_INVALID = "context_invalid"
    PRECONDITION_FAILED = "precondition_failed"
    INVARIANT_VIOLATED = "invariant_violated"
    DUPLICATE_COMMAND = "duplicate_command"
    POLICY_CONFIGURATION_INVALID = "policy_configuration_invalid"


class CommandEnvelope(BaseModel):
    """A command request that describes intent but performs no action."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    command_id: UUID = Field(default_factory=uuid4)
    command: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")
    actor_id: str | None = Field(default=None, min_length=1, max_length=128)
    requested_at: datetime
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("requested_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("requested_at must be timezone-aware")
        return value


class PolicyContext(BaseModel):
    """Facts presented to evaluation; they are assertions, not trusted sensor data."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    observed_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value


class Policy(BaseModel):
    """Illustrative declarative policy used by the reference evaluator."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    policy_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    allowed_commands: frozenset[str] = frozenset()
    authorized_actors: frozenset[str] = frozenset()
    required_facts: frozenset[str] = frozenset()
    max_context_age_seconds: int = Field(default=5, ge=0, le=86400)
    required_conditions: tuple[dict[str, Any], ...] = ()


class DecisionEvidence(BaseModel):
    """Structured explanation of a single policy evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    decision_id: UUID = Field(default_factory=uuid4)
    command_id: UUID
    policy_id: str
    policy_version: str
    status: DecisionStatus
    reason_codes: tuple[ReasonCode, ...]
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    context_observed_at: datetime
    evidence: dict[str, Any] = Field(default_factory=dict)
