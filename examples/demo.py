"""Run a small, synthetic Sentinel Interlock demonstration.

This script evaluates example requests only. It never executes commands or
connects to railway, industrial, cloud, or production systems.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinel_interlock.adapters import evaluate_railway_movement, evaluate_service_restart
from sentinel_interlock.serialization import serialize_evidence


def main() -> None:
    now = datetime.now(UTC)
    scenarios = [
        (
            "Railway-inspired scenario — all synthetic preconditions true",
            evaluate_railway_movement(
                actor_id="simulated_dispatcher",
                observed_at=now,
                route_clear=True,
                section_unoccupied=True,
                movement_authority_valid=True,
                now=now,
            ),
        ),
        (
            "Railway-inspired scenario — section reported occupied",
            evaluate_railway_movement(
                actor_id="simulated_dispatcher",
                observed_at=now,
                route_clear=True,
                section_unoccupied=False,
                movement_authority_valid=True,
                now=now,
            ),
        ),
        (
            "IT restart scenario — stale context",
            evaluate_service_restart(
                actor_id="simulated_operator",
                observed_at=now - timedelta(seconds=31),
                maintenance_window_open=True,
                change_approved=True,
                backup_verified=True,
                now=now,
            ),
        ),
    ]

    for title, decision in scenarios:
        print(f"\n=== {title} ===")
        print(f"Decision: {decision.status.value.upper()}")
        print(
            "Reasons: "
            + (", ".join(code.value for code in decision.reason_codes) or "none")
        )
        print("Evidence JSON:")
        print(serialize_evidence(decision))


if __name__ == "__main__":
    main()
