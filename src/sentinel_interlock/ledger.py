"""An in-memory evidence ledger for demonstrations only."""

from .models import DecisionEvidence


class InMemoryEvidenceLedger:
    """Keep decisions for this process lifetime; this is not durable or tamper-evident."""

    def __init__(self) -> None:
        self._entries: list[DecisionEvidence] = []

    def append(self, entry: DecisionEvidence) -> None:
        self._entries.append(entry)

    def entries(self) -> tuple[DecisionEvidence, ...]:
        return tuple(self._entries)
