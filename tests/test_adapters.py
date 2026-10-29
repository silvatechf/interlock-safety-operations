from datetime import UTC, datetime, timedelta

from sentinel_interlock.adapters import (
    evaluate_railway_movement,
    evaluate_service_restart,
)
from sentinel_interlock.models import DecisionStatus, ReasonCode

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_railway_simulation_allows_only_when_all_synthetic_preconditions_hold() -> None:
    result = evaluate_railway_movement(
        actor_id="simulated_dispatcher",
        observed_at=NOW,
        route_clear=True,
        section_unoccupied=True,
        movement_authority_valid=True,
        now=NOW,
    )
    assert result.status is DecisionStatus.ALLOW


def test_railway_simulation_denies_if_section_occupied() -> None:
    result = evaluate_railway_movement(
        actor_id="simulated_dispatcher",
        observed_at=NOW,
        route_clear=True,
        section_unoccupied=False,
        movement_authority_valid=True,
        now=NOW,
    )
    assert result.status is DecisionStatus.DENY
    assert ReasonCode.PRECONDITION_FAILED in result.reason_codes


def test_railway_simulation_denies_missing_fact() -> None:
    result = evaluate_railway_movement(
        actor_id="simulated_dispatcher",
        observed_at=NOW,
        route_clear=True,
        section_unoccupied=None,
        movement_authority_valid=True,
        now=NOW,
    )
    assert result.status is DecisionStatus.DENY
    assert ReasonCode.PRECONDITION_FAILED in result.reason_codes


def test_it_restart_requires_approval_window_and_verified_backup() -> None:
    result = evaluate_service_restart(
        actor_id="simulated_operator",
        observed_at=NOW,
        maintenance_window_open=True,
        change_approved=True,
        backup_verified=True,
        now=NOW,
    )
    assert result.status is DecisionStatus.ALLOW


def test_it_restart_denies_without_change_approval() -> None:
    result = evaluate_service_restart(
        actor_id="simulated_operator",
        observed_at=NOW,
        maintenance_window_open=True,
        change_approved=False,
        backup_verified=True,
        now=NOW,
    )
    assert result.status is DecisionStatus.DENY
    assert ReasonCode.PRECONDITION_FAILED in result.reason_codes


def test_it_restart_denies_stale_context() -> None:
    result = evaluate_service_restart(
        actor_id="simulated_operator",
        observed_at=NOW - timedelta(seconds=31),
        maintenance_window_open=True,
        change_approved=True,
        backup_verified=True,
        now=NOW,
    )
    assert result.status is DecisionStatus.DENY
    assert ReasonCode.CONTEXT_STALE in result.reason_codes
