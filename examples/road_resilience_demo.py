"""Run the offline, synthetic road-resilience scenario suite.

The output is an information-review classification only. It is not navigation,
right-of-way guidance, an emergency alert, or a control instruction.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinel_interlock.road_simulator import build_road_scenarios, evaluate_road_scenario


def main() -> None:
    now = datetime.now(UTC)
    for scenario in build_road_scenarios(now):
        result = evaluate_road_scenario(scenario)
        print(f"\n=== {result.scenario_id} ===")
        print(f"Review status: {result.review_status.value}")
        print(f"Findings: {', '.join(code.value for code in result.findings) or 'none'}")
        print(
            "Events: "
            f"accepted={result.accepted_event_count}, "
            f"rejected={result.rejected_event_count}, "
            f"indeterminate={result.indeterminate_event_count}"
        )
        if result.conflicting_subjects:
            print(f"Conflicting subjects: {', '.join(result.conflicting_subjects)}")


if __name__ == "__main__":
    main()
