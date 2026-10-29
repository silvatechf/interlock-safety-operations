from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from sentinel_interlock.engine import evaluate
from sentinel_interlock.models import (
    CommandEnvelope,
    DecisionStatus,
    Policy,
    PolicyContext,
    ReasonCode,
)

BASE = datetime(2026, 1, 1, tzinfo=UTC)
POLICY = Policy(
    policy_id="property-test",
    version="1",
    allowed_commands=frozenset({"demo.run"}),
    authorized_actors=frozenset({"operator"}),
    required_facts=frozenset({"ready"}),
    max_context_age_seconds=10,
    required_conditions=({"fact": "ready", "equals": True},),
)


@given(actor=st.none() | st.text(min_size=1, max_size=30).filter(lambda value: value != "operator"))
def test_any_missing_or_unlisted_actor_is_denied(actor: str | None) -> None:
    command = CommandEnvelope(
        command="demo.run",
        actor_id=actor,
        requested_at=BASE,
    )
    context = PolicyContext(observed_at=BASE, facts={"ready": True})
    result = evaluate(command, context, POLICY, now=BASE)
    assert result.status is DecisionStatus.DENY
    expected = (
        ReasonCode.AUTHENTICATION_REQUIRED
        if actor is None
        else ReasonCode.ACTOR_NOT_AUTHORIZED
    )
    assert expected in result.reason_codes


@given(age=st.integers(min_value=11, max_value=86400))
def test_any_context_older_than_policy_limit_is_denied(age: int) -> None:
    observed_at = BASE
    now = BASE + timedelta(seconds=age)
    command = CommandEnvelope(
        command="demo.run",
        actor_id="operator",
        requested_at=BASE,
    )
    context = PolicyContext(observed_at=observed_at, facts={"ready": True})
    result = evaluate(command, context, POLICY, now=now)
    assert result.status is DecisionStatus.DENY
    assert ReasonCode.CONTEXT_STALE in result.reason_codes
