"""Process-local duplicate-command protection for demonstrations."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Lock
from uuid import UUID

from .engine import evaluate
from .ledger import InMemoryEvidenceLedger
from .models import (
    CommandEnvelope,
    DecisionEvidence,
    DecisionStatus,
    Policy,
    PolicyContext,
    ReasonCode,
)


class EvaluationSession:
    """Serialize evaluations and reject command IDs already seen in this process.

    This guard is process-local. It does not survive restarts and cannot coordinate
    multiple processes or hosts. It is not durable idempotency.
    """

    def __init__(self, ledger: InMemoryEvidenceLedger | None = None) -> None:
        self._ledger = ledger if ledger is not None else InMemoryEvidenceLedger()
        self._seen_command_ids: set[UUID] = set()
        self._lock = Lock()

    @property
    def ledger(self) -> InMemoryEvidenceLedger:
        return self._ledger

    def evaluate(
        self,
        command: CommandEnvelope,
        context: PolicyContext,
        policy: Policy,
        *,
        now: datetime | None = None,
    ) -> DecisionEvidence:
        """Evaluate once per command ID within this process-local session."""
        with self._lock:
            evaluated_at = now or datetime.now(UTC)
            if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
                raise ValueError("now must be timezone-aware")

            if command.command_id in self._seen_command_ids:
                decision = DecisionEvidence(
                    command_id=command.command_id,
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    status=DecisionStatus.DENY,
                    reason_codes=(ReasonCode.DUPLICATE_COMMAND,),
                    evaluated_at=evaluated_at,
                    context_observed_at=context.observed_at,
                    evidence={
                        "command": command.command,
                        "duplicate": True,
                        "scope": "process-local",
                    },
                )
            else:
                decision = evaluate(command, context, policy, now=evaluated_at)
                self._seen_command_ids.add(command.command_id)

            self._ledger.append(decision)
            return decision
