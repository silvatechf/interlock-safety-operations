from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from sentinel_interlock.evidence_chain import (
    GENESIS_HASH,
    EvidenceChain,
    EvidenceChainRecord,
    _record_hash,
)
from sentinel_interlock.models import DecisionEvidence, DecisionStatus, ReasonCode

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def make_entry() -> DecisionEvidence:
    return DecisionEvidence(
        command_id=uuid4(),
        policy_id="policy",
        policy_version="1",
        status=DecisionStatus.ALLOW,
        reason_codes=(),
        context_observed_at=NOW,
        evaluated_at=NOW,
        evidence={"source": "synthetic"},
    )


def test_first_record_uses_genesis_and_verifies() -> None:
    chain = EvidenceChain()
    first = chain.append(make_entry())

    assert first.sequence == 0
    assert first.previous_hash == GENESIS_HASH
    assert len(first.record_hash) == 64
    assert EvidenceChain.verify(chain.records())


def test_records_are_linked_and_snapshot_is_immutable() -> None:
    chain = EvidenceChain()
    first = chain.append(make_entry())
    snapshot = chain.records()
    second = chain.append(make_entry())

    assert second.sequence == 1
    assert second.previous_hash == first.record_hash
    assert len(snapshot) == 1
    assert EvidenceChain.verify(chain.records())


def test_payload_modification_is_detected() -> None:
    chain = EvidenceChain()
    chain.append(make_entry())
    records = chain.records()
    tampered = (replace(records[0], payload=records[0].payload + " "),)

    assert not EvidenceChain.verify(tampered)


def test_middle_record_removal_is_detected() -> None:
    chain = EvidenceChain()
    for _ in range(3):
        chain.append(make_entry())

    records = chain.records()
    assert not EvidenceChain.verify((records[0], records[2]))


def test_record_reordering_is_detected() -> None:
    chain = EvidenceChain()
    for _ in range(3):
        chain.append(make_entry())

    records = chain.records()
    assert not EvidenceChain.verify((records[1], records[0], records[2]))


def test_previous_hash_modification_is_detected() -> None:
    chain = EvidenceChain()
    chain.append(make_entry())
    chain.append(make_entry())
    records = chain.records()
    broken = (records[0], replace(records[1], previous_hash=GENESIS_HASH))

    assert not EvidenceChain.verify(broken)


def test_hash_chain_does_not_hide_invalid_evidence_payload() -> None:
    chain = EvidenceChain()
    chain.append(make_entry())
    record = chain.records()[0]
    invalid = replace(record, payload="not-json")
    invalid = replace(
        invalid,
        record_hash=_record_hash(
            invalid.sequence, invalid.previous_hash, invalid.payload
        ),
    )

    assert not EvidenceChain.verify((invalid,))


def test_identical_evidence_produces_identical_record_hash() -> None:
    decision = make_entry()
    first_chain = EvidenceChain()
    second_chain = EvidenceChain()

    first = first_chain.append(decision)
    second = second_chain.append(decision)

    assert first.payload == second.payload
    assert first.record_hash == second.record_hash


def test_final_suffix_truncation_requires_external_checkpoint() -> None:
    chain = EvidenceChain()
    chain.append(make_entry())
    chain.append(make_entry())
    records = chain.records()

    # A valid prefix is internally consistent; the verifier cannot know
    # whether later records once existed without an external checkpoint.
    assert EvidenceChain.verify(records[:1])


@pytest.mark.parametrize("records", [None, "not-a-record-sequence", [None], [object()]])
def test_malformed_record_collections_fail_closed(records: object) -> None:
    assert not EvidenceChain.verify(records)  # type: ignore[arg-type]


def test_boolean_sequence_number_is_rejected() -> None:
    record = EvidenceChainRecord(
        sequence=True,
        previous_hash=GENESIS_HASH,
        payload="{}",
        record_hash="0" * 64,
    )
    assert not EvidenceChain.verify((record,))


def test_decision_status_and_reason_codes_must_agree() -> None:
    with pytest.raises(ValidationError, match="ALLOW decisions"):
        DecisionEvidence(
            command_id=uuid4(),
            policy_id="policy",
            policy_version="1",
            status=DecisionStatus.ALLOW,
            reason_codes=(ReasonCode.PRECONDITION_FAILED,),
            context_observed_at=NOW,
        )

    with pytest.raises(ValidationError, match="DENY decisions"):
        DecisionEvidence(
            command_id=uuid4(),
            policy_id="policy",
            policy_version="1",
            status=DecisionStatus.DENY,
            reason_codes=(),
            context_observed_at=NOW,
        )
