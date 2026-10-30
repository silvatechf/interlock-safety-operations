"""Deterministic, offline road-disruption scenarios using synthetic events only.

This module classifies information for human review. It never computes right of
way, recommends a route, instructs a driver, or controls road infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from .events import (
    EventReasonCode,
    EventValidationResult,
    EventValidationStatus,
    OperationalEvent,
    validate_event,
)


class RoadFindingCode(StrEnum):
    EVENT_ACCEPTED = "event_accepted"
    EVENT_REJECTED = "event_rejected"
    EVENT_INDETERMINATE = "event_indeterminate"
    CONTRADICTORY_REPORTS = "contradictory_reports"
    TRAFFIC_SIGNAL_OUTAGE_REPORTED = "traffic_signal_outage_reported"
    HUMAN_REVIEW_REQUIRED = "human_review_required"


class RoadReviewStatus(StrEnum):
    CONSISTENT = "consistent"
    REVIEW_REQUIRED = "review_required"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class RoadScenario:
    """A reproducible scenario assembled from synthetic event fixtures."""

    scenario_id: str
    description: str
    evaluated_at: datetime
    trusted_sources: frozenset[str]
    events: tuple[OperationalEvent, ...]


@dataclass(frozen=True, slots=True)
class RoadEventOutcome:
    event_id: str
    validation: EventValidationResult


@dataclass(frozen=True, slots=True)
class RoadScenarioResult:
    scenario_id: str
    description: str
    review_status: RoadReviewStatus
    findings: tuple[RoadFindingCode, ...]
    event_outcomes: tuple[RoadEventOutcome, ...]
    conflicting_subjects: tuple[str, ...]
    accepted_event_count: int
    rejected_event_count: int
    indeterminate_event_count: int
    evaluated_at: datetime


def _claim(event: OperationalEvent) -> tuple[str, str] | None:
    """Return a bounded subject/state claim; ignore malformed domain payloads."""
    subject = event.payload.get("subject_id")
    state = event.payload.get("state")
    if isinstance(subject, str) and subject and isinstance(state, str) and state:
        return subject, state
    return None


def evaluate_road_scenario(scenario: RoadScenario) -> RoadScenarioResult:
    """Validate a scenario and surface conflicts without making traffic decisions."""
    if scenario.evaluated_at.tzinfo is None or scenario.evaluated_at.utcoffset() is None:
        raise ValueError("scenario evaluated_at must be timezone-aware")

    seen_event_ids: set[str] = set()
    last_sequence_by_source: dict[str, int] = {}
    outcomes: list[RoadEventOutcome] = []
    claims_by_subject: dict[str, set[str]] = {}
    findings: list[RoadFindingCode] = []

    for event in scenario.events:
        result = validate_event(
            event,
            trusted_sources=scenario.trusted_sources,
            now=scenario.evaluated_at,
            seen_event_ids=frozenset(seen_event_ids),
            last_sequence_by_source=last_sequence_by_source,
        )
        outcomes.append(RoadEventOutcome(event_id=event.event_id, validation=result))

        if result.status is EventValidationStatus.VALID:
            findings.append(RoadFindingCode.EVENT_ACCEPTED)
            seen_event_ids.add(event.event_id)
            last_sequence_by_source[event.source_id] = event.sequence
            claim = _claim(event)
            if claim is not None:
                subject, state = claim
                claims_by_subject.setdefault(subject, set()).add(state)
            if event.event_type == "road.traffic_signal.status":
                if event.payload.get("state") == "offline":
                    findings.append(RoadFindingCode.TRAFFIC_SIGNAL_OUTAGE_REPORTED)
        elif result.status is EventValidationStatus.REJECTED:
            findings.append(RoadFindingCode.EVENT_REJECTED)
        else:
            findings.append(RoadFindingCode.EVENT_INDETERMINATE)

    conflicts = tuple(
        sorted(subject for subject, states in claims_by_subject.items() if len(states) > 1)
    )
    if conflicts:
        findings.append(RoadFindingCode.CONTRADICTORY_REPORTS)
    if any(
        outcome.validation.status is not EventValidationStatus.VALID
        for outcome in outcomes
    ) or conflicts:
        findings.append(RoadFindingCode.HUMAN_REVIEW_REQUIRED)

    rejected = sum(
        outcome.validation.status is EventValidationStatus.REJECTED for outcome in outcomes
    )
    indeterminate = sum(
        outcome.validation.status is EventValidationStatus.INDETERMINATE
        for outcome in outcomes
    )
    accepted = len(outcomes) - rejected - indeterminate

    if conflicts or rejected:
        review_status = RoadReviewStatus.REVIEW_REQUIRED
    elif indeterminate:
        review_status = RoadReviewStatus.INDETERMINATE
    else:
        review_status = RoadReviewStatus.CONSISTENT

    return RoadScenarioResult(
        scenario_id=scenario.scenario_id,
        description=scenario.description,
        review_status=review_status,
        findings=tuple(dict.fromkeys(findings)),
        event_outcomes=tuple(outcomes),
        conflicting_subjects=conflicts,
        accepted_event_count=accepted,
        rejected_event_count=rejected,
        indeterminate_event_count=indeterminate,
        evaluated_at=scenario.evaluated_at,
    )


def build_road_scenarios(now: datetime) -> tuple[RoadScenario, ...]:
    """Build a fixed suite of offline scenarios at a caller-controlled time."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    trusted = frozenset({"sim-road-sensor-a", "sim-road-reporter-b"})
    other_source = "sim-road-reporter-b"

    def event(
        *,
        event_id: str,
        source_id: str,
        sequence: int,
        event_type: str,
        payload: dict[str, Any],
        occurred_at: datetime | None = None,
    ) -> OperationalEvent:
        occurred = occurred_at or now
        return OperationalEvent(
            event_id=event_id,
            source_id=source_id,
            event_type=event_type,
            sequence=sequence,
            occurred_at=occurred,
            expires_at=occurred + timedelta(minutes=5),
            payload=payload,
        )

    healthy = event(
        event_id="road-healthy-001",
        source_id="sim-road-sensor-a",
        sequence=1,
        event_type="road.hazard.report",
        payload={"subject_id": "segment-42", "state": "debris_reported"},
    )
    signal_outage = event(
        event_id="road-signal-001",
        source_id="sim-road-sensor-a",
        sequence=2,
        event_type="road.traffic_signal.status",
        payload={"subject_id": "junction-7", "state": "offline"},
    )
    stale = event(
        event_id="road-stale-001",
        source_id="sim-road-sensor-a",
        sequence=3,
        event_type="road.hazard.report",
        payload={"subject_id": "segment-99", "state": "debris_reported"},
        occurred_at=now - timedelta(minutes=10),
    )
    duplicate = event(
        event_id="road-duplicate-001",
        source_id="sim-road-sensor-a",
        sequence=4,
        event_type="road.hazard.report",
        payload={"subject_id": "segment-15", "state": "closure_reported"},
    )
    unknown = event(
        event_id="road-unknown-001",
        source_id="unlisted-synthetic-source",
        sequence=1,
        event_type="road.hazard.report",
        payload={"subject_id": "segment-88", "state": "blocked"},
    )
    conflict_a = event(
        event_id="road-conflict-a",
        source_id="sim-road-sensor-a",
        sequence=5,
        event_type="road.segment.status",
        payload={"subject_id": "segment-21", "state": "closed"},
    )
    conflict_b = event(
        event_id="road-conflict-b",
        source_id=other_source,
        sequence=1,
        event_type="road.segment.status",
        payload={"subject_id": "segment-21", "state": "open"},
    )

    return (
        RoadScenario(
            scenario_id="healthy-report",
            description="Fresh synthetic road hazard report from a listed source",
            evaluated_at=now,
            trusted_sources=trusted,
            events=(healthy,),
        ),
        RoadScenario(
            scenario_id="traffic-signal-outage",
            description="Synthetic report that a traffic signal is offline",
            evaluated_at=now,
            trusted_sources=trusted,
            events=(signal_outage,),
        ),
        RoadScenario(
            scenario_id="stale-report",
            description="Synthetic hazard report outside the freshness window",
            evaluated_at=now,
            trusted_sources=trusted,
            events=(stale,),
        ),
        RoadScenario(
            scenario_id="duplicate-report",
            description="The same synthetic event ID is delivered twice",
            evaluated_at=now,
            trusted_sources=trusted,
            events=(duplicate, duplicate),
        ),
        RoadScenario(
            scenario_id="unknown-source",
            description="A report claims an unlisted synthetic source identity",
            evaluated_at=now,
            trusted_sources=trusted,
            events=(unknown,),
        ),
        RoadScenario(
            scenario_id="contradictory-reports",
            description="Two synthetic sources make incompatible claims about one segment",
            evaluated_at=now,
            trusted_sources=trusted,
            events=(conflict_a, conflict_b),
        ),
    )
