"""Deterministic validation for synthetic operational events.

This module validates event claims only. It does not authenticate a source,
establish sensor provenance, correlate independent witnesses, or actuate systems.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_EVENT_PAYLOAD_BYTES: Final[int] = 1_048_576


class EventPayloadTooLargeError(ValueError):
    """Raised when a canonical event payload exceeds the configured byte limit."""



class EventValidationStatus(StrEnum):
    VALID = "valid"
    REJECTED = "rejected"
    INDETERMINATE = "indeterminate"


class EventReasonCode(StrEnum):
    SOURCE_NOT_TRUSTED = "source_not_trusted"
    EVENT_STALE = "event_stale"
    EVENT_EXPIRED = "event_expired"
    EVENT_FROM_FUTURE = "event_from_future"
    DUPLICATE_EVENT = "duplicate_event"
    SEQUENCE_NOT_ADVANCED = "sequence_not_advanced"
    PAYLOAD_DIGEST_MISMATCH = "payload_digest_mismatch"
    PAYLOAD_NOT_CANONICAL_JSON = "payload_not_canonical_json"
    PAYLOAD_TOO_LARGE = "payload_too_large"


class OperationalEvent(BaseModel):
    """Versioned synthetic event envelope; source fields are untrusted claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")
    source_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")
    event_type: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")
    sequence: int = Field(ge=0)
    occurred_at: datetime
    expires_at: datetime | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_sha256: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )

    @field_validator("occurred_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("event timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def expiry_must_follow_occurrence(self) -> OperationalEvent:
        if self.expires_at is not None and self.expires_at < self.occurred_at:
            raise ValueError("expires_at must not precede occurred_at")
        return self


class EventValidationResult(BaseModel):
    """Explainable validation outcome; VALID means checks passed, not truth."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    status: EventValidationStatus
    reason_codes: tuple[EventReasonCode, ...]
    evaluated_at: datetime
    computed_payload_sha256: str | None = None
    event_age_seconds: float | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


def canonical_payload_sha256(payload: dict[str, Any]) -> str:
    """Hash a deterministic JSON representation; this is not source authentication."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_EVENT_PAYLOAD_BYTES:
        raise EventPayloadTooLargeError("event payload exceeds maximum size")
    return hashlib.sha256(encoded).hexdigest()


def validate_event(
    event: OperationalEvent,
    *,
    trusted_sources: frozenset[str],
    now: datetime | None = None,
    max_age_seconds: int = 300,
    max_future_skew_seconds: int = 5,
    seen_event_ids: frozenset[str] = frozenset(),
    last_sequence_by_source: dict[str, int] | None = None,
) -> EventValidationResult:
    """Validate one event against caller-supplied trust and replay state.

    Replay state is supplied by the caller and is not persisted or updated here.
    A trusted_sources match is an allow-list assertion, not cryptographic identity.
    """
    evaluated_at = now or datetime.now(UTC)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if max_age_seconds < 0 or max_future_skew_seconds < 0:
        raise ValueError("time tolerances must be non-negative")

    reasons: list[EventReasonCode] = []
    if event.source_id not in trusted_sources:
        reasons.append(EventReasonCode.SOURCE_NOT_TRUSTED)
    if event.event_id in seen_event_ids:
        reasons.append(EventReasonCode.DUPLICATE_EVENT)

    previous_sequence = (last_sequence_by_source or {}).get(event.source_id)
    if previous_sequence is not None and event.sequence <= previous_sequence:
        reasons.append(EventReasonCode.SEQUENCE_NOT_ADVANCED)

    age_seconds = (evaluated_at - event.occurred_at).total_seconds()
    if age_seconds > max_age_seconds:
        reasons.append(EventReasonCode.EVENT_STALE)
    elif age_seconds < -max_future_skew_seconds:
        reasons.append(EventReasonCode.EVENT_FROM_FUTURE)

    if event.expires_at is not None and evaluated_at > event.expires_at:
        reasons.append(EventReasonCode.EVENT_EXPIRED)

    computed_digest: str | None
    try:
        computed_digest = canonical_payload_sha256(event.payload)
    except EventPayloadTooLargeError:
        computed_digest = None
        reasons.append(EventReasonCode.PAYLOAD_TOO_LARGE)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        computed_digest = None
        reasons.append(EventReasonCode.PAYLOAD_NOT_CANONICAL_JSON)

    if computed_digest is not None and event.payload_sha256 is not None:
        if computed_digest != event.payload_sha256:
            reasons.append(EventReasonCode.PAYLOAD_DIGEST_MISMATCH)

    unique_reasons = tuple(dict.fromkeys(reasons))
    rejected_reasons = {
        EventReasonCode.SOURCE_NOT_TRUSTED,
        EventReasonCode.DUPLICATE_EVENT,
        EventReasonCode.SEQUENCE_NOT_ADVANCED,
        EventReasonCode.EVENT_STALE,
        EventReasonCode.EVENT_EXPIRED,
        EventReasonCode.PAYLOAD_NOT_CANONICAL_JSON,
        EventReasonCode.PAYLOAD_TOO_LARGE,
        EventReasonCode.PAYLOAD_DIGEST_MISMATCH,
    }
    if any(reason in rejected_reasons for reason in unique_reasons):
        status = EventValidationStatus.REJECTED
    elif unique_reasons:
        status = EventValidationStatus.INDETERMINATE
    else:
        status = EventValidationStatus.VALID

    return EventValidationResult(
        event_id=event.event_id,
        status=status,
        reason_codes=unique_reasons,
        evaluated_at=evaluated_at,
        computed_payload_sha256=computed_digest,
        event_age_seconds=age_seconds,
        evidence={
            "source_allow_list_match": event.source_id in trusted_sources,
            "sequence_previous": previous_sequence,
            "sequence_current": event.sequence,
            "payload_digest_self_consistent": (
                None
                if event.payload_sha256 is None or computed_digest is None
                else event.payload_sha256 == computed_digest
            ),
            "replay_state_is_caller_supplied": True,
        },
    )
