from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from sentinel_interlock.engine import evaluate
from sentinel_interlock.models import (
    CommandEnvelope,
    DecisionStatus,
    Policy,
    PolicyContext,
    ReasonCode,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def build_policy(**overrides: object) -> Policy:
    values: dict[str, object] = {
        "policy_id": "test-policy",
        "version": "1",
        "allowed_commands": frozenset({"demo.start"}),
        "authorized_actors": frozenset({"operator-1"}),
        "required_facts": frozenset({"system_ready"}),
        "max_context_age_seconds": 5,
        "required_conditions": ({"fact": "system_ready", "equals": True},),
    }
    values.update(overrides)
    return Policy(**values)


def build_command(**overrides: object) -> CommandEnvelope:
    values: dict[str, object] = {
        "command": "demo.start",
        "actor_id": "operator-1",
        "requested_at": NOW,
        "context": {},
    }
    values.update(overrides)
    return CommandEnvelope(**values)


def build_context(
    *, observed_at: datetime = NOW, facts: dict[str, object] | None = None
) -> PolicyContext:
    selected_facts = {"system_ready": True} if facts is None else facts
    return PolicyContext(observed_at=observed_at, facts=selected_facts)


def test_explicit_preconditions_allow() -> None:
    result = evaluate(build_command(), build_context(), build_policy(), now=NOW)
    assert result.status is DecisionStatus.ALLOW
    assert result.reason_codes == ()


def test_missing_actor_denies_by_default() -> None:
    result = evaluate(build_command(actor_id=None), build_context(), build_policy(), now=NOW)
    assert result.status is DecisionStatus.DENY
    assert ReasonCode.AUTHENTICATION_REQUIRED in result.reason_codes


def test_unauthorized_actor_is_denied() -> None:
    result = evaluate(build_command(actor_id="unknown"), build_context(), build_policy(), now=NOW)
    assert ReasonCode.ACTOR_NOT_AUTHORIZED in result.reason_codes


def test_unknown_command_is_denied() -> None:
    result = evaluate(
        build_command(command="demo.delete_everything"),
        build_context(),
        build_policy(),
        now=NOW,
    )
    assert ReasonCode.COMMAND_NOT_ALLOWED in result.reason_codes


def test_missing_context_fact_denies() -> None:
    result = evaluate(build_command(), build_context(facts={}), build_policy(), now=NOW)
    assert result.status is DecisionStatus.DENY
    assert ReasonCode.CONTEXT_MISSING in result.reason_codes


def test_stale_context_denies() -> None:
    context = build_context(observed_at=NOW - timedelta(seconds=6))
    result = evaluate(build_command(), context, build_policy(), now=NOW)
    assert ReasonCode.CONTEXT_STALE in result.reason_codes


def test_future_context_timestamp_denies() -> None:
    context = build_context(observed_at=NOW + timedelta(seconds=1))
    result = evaluate(build_command(), context, build_policy(), now=NOW)
    assert ReasonCode.CONTEXT_INVALID in result.reason_codes


def test_failed_condition_denies_and_explains_fact() -> None:
    context = build_context(facts={"system_ready": False})
    result = evaluate(build_command(), context, build_policy(), now=NOW)
    assert ReasonCode.PRECONDITION_FAILED in result.reason_codes
    assert result.evidence["failed_conditions"] == [
        {"fact": "system_ready", "expected": True, "actual": False}
    ]


def test_malformed_policy_condition_is_rejected_at_construction() -> None:
    with pytest.raises(ValidationError):
        build_policy(required_conditions=({"fact": "system_ready"},))


def test_blank_policy_members_are_rejected() -> None:
    with pytest.raises(ValidationError):
        build_policy(allowed_commands=frozenset({"demo.start", " "}))


def test_naive_evaluation_time_is_rejected() -> None:
    naive = datetime(2026, 1, 1, 12, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate(build_command(), build_context(), build_policy(), now=naive)


def test_evaluation_never_executes_commands() -> None:
    result = evaluate(build_command(), build_context(), build_policy(), now=NOW)
    assert result.command_id is not None
    assert result.status is DecisionStatus.ALLOW
