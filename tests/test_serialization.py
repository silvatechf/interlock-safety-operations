from datetime import UTC, datetime
from uuid import uuid4

import pytest

from sentinel_interlock.models import DecisionEvidence, DecisionStatus, ReasonCode
from sentinel_interlock.serialization import (
    EVIDENCE_SCHEMA_VERSION,
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
    assert serialize_evidence(decision) == serialize_evidence(decision)


def test_schema_version_is_explicit() -> None:
    import json

    payload = json.loads(serialize_evidence(make_decision()))
    assert payload["schema_version"] == EVIDENCE_SCHEMA_VERSION


def test_unknown_schema_version_is_rejected() -> None:
    import json

    payload = json.loads(serialize_evidence(make_decision()))
    payload["schema_version"] = EVIDENCE_SCHEMA_VERSION + 1
    with pytest.raises(EvidenceSerializationError, match="unsupported"):
        deserialize_evidence(json.dumps(payload))


@pytest.mark.parametrize("payload", ["{", "[]", '{"schema_version": 1, "decision": []}'])
def test_malformed_payload_is_rejected(payload: str) -> None:
    with pytest.raises(EvidenceSerializationError):
        deserialize_evidence(payload)
