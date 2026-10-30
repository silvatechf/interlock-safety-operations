from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from sentinel_interlock.events import (
    EventReasonCode,
    EventValidationStatus,
    OperationalEvent,
    canonical_payload_sha256,
    validate_event,
)

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
TRUSTED = frozenset({"road-sensor-a"})


def make_event(**overrides: object) -> OperationalEvent:
    values: dict[str, object] = {
        "event_id": "event-001",
        "source_id": "road-sensor-a",
        "event_type": "road.traffic_light_outage",
        "sequence": 1,
        "occurred_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "payload": {"intersection": "junction-42", "status": "offline"},
    }
    values.update(overrides)
    return OperationalEvent(**values)


def test_valid_event_passes_explicit_checks() -> None:
    event = make_event()
    result = validate_event(event, trusted_sources=TRUSTED, now=NOW)

    assert result.status is EventValidationStatus.VALID
    assert result.reason_codes == ()
    assert result.computed_payload_sha256 == canonical_payload_sha256(event.payload)


def test_unlisted_source_is_rejected() -> None:
    result = validate_event(
        make_event(source_id="unknown-source"),
        trusted_sources=TRUSTED,
        now=NOW,
    )

    assert result.status is EventValidationStatus.REJECTED
    assert EventReasonCode.SOURCE_NOT_TRUSTED in result.reason_codes


def test_stale_event_is_rejected() -> None:
    result = validate_event(
        make_event(occurred_at=NOW - timedelta(seconds=301)),
        trusted_sources=TRUSTED,
        now=NOW,
        max_age_seconds=300,
    )

    assert result.status is EventValidationStatus.REJECTED
    assert EventReasonCode.EVENT_STALE in result.reason_codes


def test_expired_event_is_rejected() -> None:
    result = validate_event(
        make_event(
            occurred_at=NOW - timedelta(minutes=10),
            expires_at=NOW - timedelta(seconds=1),
        ),
        trusted_sources=TRUSTED,
        now=NOW,
    )

    assert EventReasonCode.EVENT_EXPIRED in result.reason_codes
    assert result.status is EventValidationStatus.REJECTED


def test_future_event_beyond_tolerance_is_indeterminate() -> None:
    result = validate_event(
        make_event(occurred_at=NOW + timedelta(seconds=6), expires_at=None),
        trusted_sources=TRUSTED,
        now=NOW,
        max_future_skew_seconds=5,
    )

    assert result.status is EventValidationStatus.INDETERMINATE
    assert result.reason_codes == (EventReasonCode.EVENT_FROM_FUTURE,)


def test_duplicate_event_id_is_rejected() -> None:
    result = validate_event(
        make_event(),
        trusted_sources=TRUSTED,
        now=NOW,
        seen_event_ids=frozenset({"event-001"}),
    )

    assert EventReasonCode.DUPLICATE_EVENT in result.reason_codes


def test_non_advanced_sequence_is_rejected() -> None:
    result = validate_event(
        make_event(sequence=8),
        trusted_sources=TRUSTED,
        now=NOW,
        last_sequence_by_source={"road-sensor-a": 8},
    )

    assert EventReasonCode.SEQUENCE_NOT_ADVANCED in result.reason_codes


def test_payload_digest_mismatch_is_rejected() -> None:
    event = make_event(payload_sha256="0" * 64)
    result = validate_event(event, trusted_sources=TRUSTED, now=NOW)

    assert result.status is EventValidationStatus.REJECTED
    assert EventReasonCode.PAYLOAD_DIGEST_MISMATCH in result.reason_codes


def test_payload_digest_is_deterministic_across_key_order() -> None:
    first = canonical_payload_sha256({"a": 1, "b": {"x": 2, "y": 3}})
    second = canonical_payload_sha256({"b": {"y": 3, "x": 2}, "a": 1})
    assert first == second


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_event(occurred_at=datetime(2026, 10, 30, 12, 0))


def test_expiry_before_occurrence_is_rejected() -> None:
    with pytest.raises(ValidationError, match="expires_at"):
        make_event(expires_at=NOW - timedelta(seconds=1))


def test_negative_time_tolerance_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        validate_event(
            make_event(),
            trusted_sources=TRUSTED,
            now=NOW,
            max_age_seconds=-1,
        )


def test_replay_state_is_not_mutated() -> None:
    seen = frozenset()
    last_sequence = {"road-sensor-a": 0}
    validate_event(
        make_event(),
        trusted_sources=TRUSTED,
        now=NOW,
        seen_event_ids=seen,
        last_sequence_by_source=last_sequence,
    )
    assert seen == frozenset()
    assert last_sequence == {"road-sensor-a": 0}



def test_oversized_payload_is_rejected() -> None:
    event = make_event(payload={"report": "x" * 1_048_577})
    result = validate_event(event, trusted_sources=TRUSTED, now=NOW)

    assert result.status is EventValidationStatus.REJECTED
    assert EventReasonCode.PAYLOAD_TOO_LARGE in result.reason_codes


def test_non_json_payload_is_rejected() -> None:
    event = make_event(payload={"not_json": object()})
    result = validate_event(event, trusted_sources=TRUSTED, now=NOW)

    assert result.status is EventValidationStatus.REJECTED
    assert EventReasonCode.PAYLOAD_NOT_CANONICAL_JSON in result.reason_codes
