from datetime import UTC, datetime
from uuid import uuid4

from sentinel_interlock.ledger import InMemoryEvidenceLedger
from sentinel_interlock.models import DecisionEvidence, DecisionStatus

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def make_entry() -> DecisionEvidence:
    return DecisionEvidence(
        command_id=uuid4(),
        policy_id="policy",
        policy_version="1",
        status=DecisionStatus.DENY,
        reason_codes=(),
        context_observed_at=NOW,
        evaluated_at=NOW,
    )


def test_entries_returns_snapshot() -> None:
    ledger = InMemoryEvidenceLedger()
    first = make_entry()
    ledger.append(first)
    snapshot = ledger.entries()
    ledger.append(make_entry())
    assert snapshot == (first,)
    assert len(ledger.entries()) == 2
