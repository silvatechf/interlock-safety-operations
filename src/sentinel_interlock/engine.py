from datetime import datetime, timezone
from typing import Any

from .models import CommandEnvelope, DecisionEvidence, DecisionStatus, Policy, PolicyContext, ReasonCode


def evaluate(command: CommandEnvelope, context: PolicyContext, policy: Policy, *, now: datetime | None = None) -> DecisionEvidence:
    """Evaluate policy only; never execute or actuate the command."""
    evaluated_at = now or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    reasons: list[ReasonCode] = []
    if command.actor_id is None:
        reasons.append(ReasonCode.AUTHENTICATION_REQUIRED)
    elif command.actor_id not in policy.authorized_actors:
        reasons.append(ReasonCode.ACTOR_NOT_AUTHORIZED)
    if command.command not in policy.allowed_commands:
        reasons.append(ReasonCode.COMMAND_NOT_ALLOWED)

    missing = sorted(policy.required_facts.difference(context.facts.keys()))
    if missing:
        reasons.append(ReasonCode.CONTEXT_MISSING)
    age_seconds = (evaluated_at - context.observed_at).total_seconds()
    if age_seconds < 0:
        reasons.append(ReasonCode.CONTEXT_INVALID)
    elif age_seconds > policy.max_context_age_seconds:
        reasons.append(ReasonCode.CONTEXT_STALE)

    failed_conditions: list[dict[str, Any]] = []
    for condition in policy.required_conditions:
        fact_name = condition.get("fact")
        if not isinstance(fact_name, str) or "equals" not in condition:
            reasons.append(ReasonCode.POLICY_CONFIGURATION_INVALID)
            continue
        if fact_name not in context.facts:
            reasons.append(ReasonCode.PRECONDITION_FAILED)
            failed_conditions.append({"fact": fact_name, "reason": "missing"})
        elif context.facts[fact_name] != condition["equals"]:
            reasons.append(ReasonCode.PRECONDITION_FAILED)
            failed_conditions.append({"fact": fact_name, "expected": condition["equals"], "actual": context.facts[fact_name]})

    unique_reasons = tuple(dict.fromkeys(reasons))
    return DecisionEvidence(
        command_id=command.command_id,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        status=DecisionStatus.DENY if unique_reasons else DecisionStatus.ALLOW,
        reason_codes=unique_reasons,
        evaluated_at=evaluated_at,
        context_observed_at=context.observed_at,
        evidence={"command": command.command, "actor_id": command.actor_id, "context_age_seconds": age_seconds, "missing_facts": missing, "failed_conditions": failed_conditions},
    )
