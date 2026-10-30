from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from sentinel_interlock.events import (
    EventReasonCode,
    EventValidationStatus,
    OperationalEvent,
    canonical_payload_sha256,
    validate_event,
)

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
TRUSTED = frozenset({"source-a"})


@given(age=st.integers(min_value=301, max_value=86_400))
def test_any_event_older_than_freshness_limit_is_rejected(age: int) -> None:
    event = OperationalEvent(
        event_id="stale-event",
        source_id="source-a",
        event_type="road.hazard",
        sequence=1,
        occurred_at=NOW - timedelta(seconds=age),
    )
    result = validate_event(
        event,
        trusted_sources=TRUSTED,
        now=NOW,
        max_age_seconds=300,
    )

    assert result.status is EventValidationStatus.REJECTED
    assert EventReasonCode.EVENT_STALE in result.reason_codes


@given(previous=st.integers(min_value=0, max_value=1_000_000))
def test_any_sequence_not_greater_than_previous_is_rejected(previous: int) -> None:
    event = OperationalEvent(
        event_id="sequence-event",
        source_id="source-a",
        event_type="road.hazard",
        sequence=previous,
        occurred_at=NOW,
    )
    result = validate_event(
        event,
        trusted_sources=TRUSTED,
        now=NOW,
        last_sequence_by_source={"source-a": previous},
    )

    assert result.status is EventValidationStatus.REJECTED
    assert EventReasonCode.SEQUENCE_NOT_ADVANCED in result.reason_codes


@given(payload=st.dictionaries(
    keys=st.text(min_size=1, max_size=12),
    values=st.integers(min_value=-1_000_000, max_value=1_000_000),
    max_size=20,
))
def test_payload_digest_is_stable_for_dictionary_key_order(payload: dict[str, int]) -> None:
    reversed_payload = dict(reversed(list(payload.items())))
    assert canonical_payload_sha256(payload) == canonical_payload_sha256(reversed_payload)
