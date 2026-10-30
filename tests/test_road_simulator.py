from datetime import UTC, datetime

from sentinel_interlock.road_simulator import (
    RoadFindingCode,
    RoadReviewStatus,
    build_road_scenarios,
    evaluate_road_scenario,
)

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def results_by_id():
    return {
        scenario.scenario_id: evaluate_road_scenario(scenario)
        for scenario in build_road_scenarios(NOW)
    }


def test_healthy_synthetic_report_is_consistent() -> None:
    result = results_by_id()["healthy-report"]

    assert result.review_status is RoadReviewStatus.CONSISTENT
    assert result.accepted_event_count == 1
    assert result.rejected_event_count == 0


def test_traffic_signal_outage_is_reported_without_right_of_way_decision() -> None:
    result = results_by_id()["traffic-signal-outage"]

    assert result.review_status is RoadReviewStatus.CONSISTENT
    assert RoadFindingCode.TRAFFIC_SIGNAL_OUTAGE_REPORTED in result.findings
    assert RoadFindingCode.HUMAN_REVIEW_REQUIRED not in result.findings


def test_stale_report_requires_human_review() -> None:
    result = results_by_id()["stale-report"]

    assert result.review_status is RoadReviewStatus.REVIEW_REQUIRED
    assert result.rejected_event_count == 1


def test_duplicate_delivery_is_rejected() -> None:
    result = results_by_id()["duplicate-report"]

    assert result.accepted_event_count == 1
    assert result.rejected_event_count == 1
    assert result.event_outcomes[1].validation.reason_codes[0].value == "duplicate_event"


def test_unknown_source_requires_human_review() -> None:
    result = results_by_id()["unknown-source"]

    assert result.review_status is RoadReviewStatus.REVIEW_REQUIRED
    assert result.rejected_event_count == 1


def test_conflicting_claims_are_surfaced() -> None:
    result = results_by_id()["contradictory-reports"]

    assert result.review_status is RoadReviewStatus.REVIEW_REQUIRED
    assert result.conflicting_subjects == ("segment-21",)
    assert RoadFindingCode.CONTRADICTORY_REPORTS in result.findings


def test_scenario_build_is_reproducible() -> None:
    first = results_by_id()
    second = results_by_id()

    assert first == second
