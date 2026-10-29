"""Simulation-only domain adapters for the generic policy engine.

These scenarios use caller-supplied synthetic facts. They are not connected to
railway, industrial, cloud, or production systems and must never actuate commands.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .engine import evaluate
from .models import (
    CommandEnvelope,
    DecisionEvidence,
    Policy,
    PolicyCondition,
    PolicyContext,
)

RAILWAY_POLICY = Policy(
    policy_id="railway-simulation-movement",
    version="1.0",
    allowed_commands=frozenset({"railway.request_movement"}),
    authorized_actors=frozenset({"simulated_dispatcher"}),
    required_facts=frozenset(
        {"route_clear", "section_unoccupied", "movement_authority_valid"}
    ),
    max_context_age_seconds=5,
    required_conditions=(
        PolicyCondition(fact="route_clear", equals=True),
        PolicyCondition(fact="section_unoccupied", equals=True),
        PolicyCondition(fact="movement_authority_valid", equals=True),
    ),
)

IT_POLICY = Policy(
    policy_id="it-simulation-service-restart",
    version="1.0",
    allowed_commands=frozenset({"it.restart_service"}),
    authorized_actors=frozenset({"simulated_operator"}),
    required_facts=frozenset(
        {"maintenance_window_open", "change_approved", "backup_verified"}
    ),
    max_context_age_seconds=30,
    required_conditions=(
        PolicyCondition(fact="maintenance_window_open", equals=True),
        PolicyCondition(fact="change_approved", equals=True),
        PolicyCondition(fact="backup_verified", equals=True),
    ),
)


def evaluate_railway_movement(
    *,
    actor_id: str | None,
    observed_at: datetime,
    route_clear: bool | None,
    section_unoccupied: bool | None,
    movement_authority_valid: bool | None,
    now: datetime | None = None,
) -> DecisionEvidence:
    """Evaluate a synthetic railway-inspired scenario; never controls a train."""
    facts: dict[str, Any] = {
        "route_clear": route_clear,
        "section_unoccupied": section_unoccupied,
        "movement_authority_valid": movement_authority_valid,
    }
    command = CommandEnvelope(
        command="railway.request_movement",
        actor_id=actor_id,
        requested_at=observed_at,
    )
    context = PolicyContext(observed_at=observed_at, facts=facts)
    return evaluate(command, context, RAILWAY_POLICY, now=now)


def evaluate_service_restart(
    *,
    actor_id: str | None,
    observed_at: datetime,
    maintenance_window_open: bool | None,
    change_approved: bool | None,
    backup_verified: bool | None,
    now: datetime | None = None,
) -> DecisionEvidence:
    """Evaluate a synthetic IT maintenance scenario; never restarts a service."""
    facts: dict[str, Any] = {
        "maintenance_window_open": maintenance_window_open,
        "change_approved": change_approved,
        "backup_verified": backup_verified,
    }
    command = CommandEnvelope(
        command="it.restart_service",
        actor_id=actor_id,
        requested_at=observed_at,
    )
    context = PolicyContext(observed_at=observed_at, facts=facts)
    return evaluate(command, context, IT_POLICY, now=now)
