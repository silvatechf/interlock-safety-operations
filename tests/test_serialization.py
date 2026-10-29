import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from sentinel_interlock.models import DecisionEvidence, DecisionStatus, ReasonCode
from sentinel_interlock.serialization import (
    EVIDENCE_SCHEMA_VERSION,
    MAX_EVIDENCE_PAYLOAD_BYTES,
    EvidenceSerializationError,
    deserialize_evidence,
    serialize_evidence,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def make_decision() -> DecisionEvidence:
    return DecisionEvidence(
        decision_id=uuid4(),
        command_id=uuid4(),
        policy_id="demo-policy",
        policy_version="1",
        status=DecisionStatus.DENY,
        reason_codes=(ReasonCode.CONTEXT_STALE,),
        evaluated_at=NOW,
        context_observed_at=NOW,
        evidence={"command": "demo.start", "missing_facts": ["ready"]},
    )


def test_round_trip_preserves_decision() -> None:
    decision = make_decision()
    assert deserialize_evidence(serialize_evidence(decision)) == decision


def test_serialization_is_deterministic() -> None:
    decision = make_decision()
    reordered_evidence = dict(reversed(list(decision.evidence.items())))
    equivalent_decision = decision.model_copy(update={"evidence": reordered_evidence})
    assert serialize_evidence(decision) == serialize_evidence(equivalent_decision)


def test_schema_version_is_explicit() -> None:
    payload = json.loads(serialize_evidence(make_decision()))
    assert payload["schema_version"] == EVIDENCE_SCHEMA_VERSION


def test_unknown_schema_version_is_rejected() -> None:
    payload = json.loads(serialize_evidence(make_decision()))
    payload["schema_version"] = EVIDENCE_SCHEMA_VERSION + 1
    with pytest.raises(EvidenceSerializationError, match="unsupported"):
        deserialize_evidence(json.dumps(payload))


@pytest.mark.parametrize("payload", ["{", "[]", '{"schema_version": 1, "decision": []}'])
def test_malformed_payload_is_rejected(payload: str) -> None:
    with pytest.raises(EvidenceSerializationError):
        deserialize_evidence(payload)


@pytest.mark.parametrize(
    "payload",
    [
        '{"schema_version":1,"schema_version":1,"decision":{}}',
        '{"schema_version":1,"decision":{"status":"allow","status":"deny"}}',
    ],
)
def test_duplicate_json_keys_are_rejected(payload: str) -> None:
    with pytest.raises(EvidenceSerializationError, match="duplicate JSON key"):
        deserialize_evidence(payload)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonstandard_json_constants_are_rejected(constant: str) -> None:
    payload = f'{{"schema_version":1,"decision":{{"evidence":{{"value":{constant}}}}}}}'
    with pytest.raises(EvidenceSerializationError, match="non-standard JSON constant"):
        deserialize_evidence(payload)


def test_oversized_payload_is_rejected() -> None:
    payload = " " * (MAX_EVIDENCE_PAYLOAD_BYTES + 1)
    with pytest.raises(EvidenceSerializationError, match="maximum payload size"):
        deserialize_evidence(payload)


def test_non_finite_evidence_is_rejected_on_serialization() -> None:
    decision = make_decision().model_copy(
        update={"evidence": {"nested": [float("nan")]}}
    )
    with pytest.raises(EvidenceSerializationError, match="non-finite"):
        serialize_evidence(decision)
