from datetime import UTC, datetime, timedelta
from uuid import uuid4

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
from sentinel_interlock.session import EvaluationSession

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


@given(
    repeats=st.integers(min_value=2, max_value=8),
    actor=st.sampled_from([None, "operator", "unlisted-operator"]),
    ready=st.booleans(),
)
def test_session_transition_first_evaluates_then_denies_replays(
    repeats: int, actor: str | None, ready: bool
) -> None:
    """A command ID transitions from unseen to seen and never becomes fresh again."""
    session = EvaluationSession()
    command = CommandEnvelope(
        command_id=uuid4(),
        command="demo.run",
        actor_id=actor,
        requested_at=BASE,
    )
    context = PolicyContext(observed_at=BASE, facts={"ready": ready})

    decisions = [
        session.evaluate(command, context, POLICY, now=BASE)
        for _ in range(repeats)
    ]

    assert len(session.ledger.entries()) == repeats
    assert decisions[0].reason_codes != (ReasonCode.DUPLICATE_COMMAND,)
    for replay in decisions[1:]:
        assert replay.status is DecisionStatus.DENY
        assert replay.reason_codes == (ReasonCode.DUPLICATE_COMMAND,)
        assert replay.evidence["duplicate"] is True


@given(
    actor=st.sampled_from([None, "operator", "unlisted-operator"]),
    command_name=st.sampled_from(["demo.run", "demo.unknown"]),
    ready=st.booleans(),
    age=st.integers(min_value=-1, max_value=11),
)
def test_decision_status_matches_presence_of_reasons(
    actor: str | None, command_name: str, ready: bool, age: int
) -> None:
    """The evaluator's outcome invariant holds across valid and invalid input states."""
    command = CommandEnvelope(
        command=command_name,
        actor_id=actor,
        requested_at=BASE,
    )
    context = PolicyContext(
        observed_at=BASE - timedelta(seconds=age),
        facts={"ready": ready},
    )
    result = evaluate(command, context, POLICY, now=BASE)

    if result.reason_codes:
        assert result.status is DecisionStatus.DENY
    else:
        assert result.status is DecisionStatus.ALLOW
