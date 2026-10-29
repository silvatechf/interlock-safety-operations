from datetime import UTC, datetime
from uuid import uuid4

from sentinel_interlock.models import (
    CommandEnvelope,
    DecisionStatus,
    Policy,
    PolicyContext,
    ReasonCode,
)
from sentinel_interlock.session import EvaluationSession

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
POLICY = Policy(
    policy_id="session-policy",
    version="1",
    allowed_commands=frozenset({"demo.start"}),
    authorized_actors=frozenset({"operator"}),
    required_facts=frozenset({"ready"}),
    required_conditions=({"fact": "ready", "equals": True},),
)
CONTEXT = PolicyContext(observed_at=NOW, facts={"ready": True})


def make_command(*, actor_id: str = "operator", command_id=None) -> CommandEnvelope:
    return CommandEnvelope(
        command_id=command_id or uuid4(),
        command="demo.start",
        actor_id=actor_id,
        requested_at=NOW,
    )


def test_first_command_is_evaluated_and_duplicate_is_denied() -> None:
    session = EvaluationSession()
    command = make_command()

    first = session.evaluate(command, CONTEXT, POLICY, now=NOW)
    second = session.evaluate(command, CONTEXT, POLICY, now=NOW)

    assert first.status is DecisionStatus.ALLOW
    assert second.status is DecisionStatus.DENY
    assert second.reason_codes == (ReasonCode.DUPLICATE_COMMAND,)
    assert len(session.ledger.entries()) == 2


def test_session_isolation_is_explicit() -> None:
    command = make_command()
    first_session = EvaluationSession()
    second_session = EvaluationSession()

    assert first_session.evaluate(command, CONTEXT, POLICY, now=NOW).status is DecisionStatus.ALLOW
    assert second_session.evaluate(command, CONTEXT, POLICY, now=NOW).status is DecisionStatus.ALLOW


def test_denied_command_id_is_also_marked_seen() -> None:
    session = EvaluationSession()
    command = make_command(actor_id="unknown")

    first = session.evaluate(command, CONTEXT, POLICY, now=NOW)
    second = session.evaluate(command, CONTEXT, POLICY, now=NOW)

    assert ReasonCode.ACTOR_NOT_AUTHORIZED in first.reason_codes
    assert second.reason_codes == (ReasonCode.DUPLICATE_COMMAND,)
