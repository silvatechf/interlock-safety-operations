"""Local durable approval consumption and transactional decision auditing."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .approval_audit import (
    AUDIT_GENESIS_HASH,
    ApprovalAuditRecord,
    create_audit_record,
    verify_audit_chain,
)
from .models import AccessEvidence


class ApprovalStore(Protocol):
    """Persistence boundary for replay protection and decision audit."""

    def record_decision(
        self,
        evidence: AccessEvidence,
        *,
        approval_id: str | None,
        key_id: str | None,
    ) -> None: ...

    def consume_and_record(
        self,
        approval_id: str,
        *,
        consumed_at: datetime,
        evidence: AccessEvidence,
        replay_evidence: AccessEvidence,
        key_id: str | None,
    ) -> bool: ...


class SQLiteApprovalStore:
    """Consume approvals once and persist linked audit records in one SQLite DB."""

    def __init__(self, database: str | Path, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._database = str(database)
        self._timeout_seconds = timeout_seconds
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_approvals (
                    approval_id TEXT PRIMARY KEY,
                    consumed_at TEXT NOT NULL,
                    decision_id TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_decision_audit (
                    sequence INTEGER PRIMARY KEY,
                    decision_id TEXT NOT NULL UNIQUE,
                    approval_id TEXT,
                    key_id TEXT,
                    decision TEXT NOT NULL,
                    reason_codes_json TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database, timeout=self._timeout_seconds, isolation_level=None
        )
        connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
        return connection

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        evidence: AccessEvidence,
        *,
        approval_id: str | None,
        key_id: str | None,
    ) -> None:
        row = connection.execute(
            "SELECT sequence, record_hash FROM approval_decision_audit "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 0 if row is None else row[0] + 1
        previous_hash = AUDIT_GENESIS_HASH if row is None else row[1]
        record = create_audit_record(
            evidence,
            sequence=sequence,
            approval_id=approval_id,
            key_id=key_id,
            previous_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO approval_decision_audit (
                sequence, decision_id, approval_id, key_id, decision,
                reason_codes_json, evaluated_at, policy_sha256,
                previous_hash, record_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.sequence,
                record.decision_id,
                record.approval_id,
                record.key_id,
                record.decision,
                json.dumps(record.reason_codes, separators=(",", ":")),
                record.evaluated_at,
                record.policy_sha256,
                record.previous_hash,
                record.record_hash,
            ),
        )

    def record_decision(
        self,
        evidence: AccessEvidence,
        *,
        approval_id: str | None,
        key_id: str | None,
    ) -> None:
        """Persist a non-consuming decision and its audit record atomically."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._append_audit(
                    connection, evidence, approval_id=approval_id, key_id=key_id
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def consume_and_record(
        self,
        approval_id: str,
        *,
        consumed_at: datetime,
        evidence: AccessEvidence,
        replay_evidence: AccessEvidence,
        key_id: str | None,
    ) -> bool:
        """Atomically consume once and audit the actual ALLOW or replay DENY."""
        if not approval_id.strip():
            raise ValueError("approval_id must not be blank")
        if consumed_at.tzinfo is None or consumed_at.utcoffset() is None:
            raise ValueError("consumed_at must be timezone-aware")

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO consumed_approvals (approval_id, consumed_at, decision_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(approval_id) DO NOTHING
                    """,
                    (approval_id, consumed_at.isoformat(), evidence.decision_id),
                )
                consumed = cursor.rowcount == 1
                self._append_audit(
                    connection,
                    evidence if consumed else replay_evidence,
                    approval_id=approval_id,
                    key_id=key_id,
                )
                connection.commit()
                return consumed
            except Exception:
                connection.rollback()
                raise

    def consume(
        self,
        approval_id: str,
        *,
        consumed_at: datetime,
        decision_id: str,
    ) -> bool:
        """Legacy replay-only operation; use consume_and_record in decision flows."""
        if not approval_id.strip():
            raise ValueError("approval_id must not be blank")
        if consumed_at.tzinfo is None or consumed_at.utcoffset() is None:
            raise ValueError("consumed_at must be timezone-aware")
        if not decision_id.strip():
            raise ValueError("decision_id must not be blank")

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO consumed_approvals (approval_id, consumed_at, decision_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(approval_id) DO NOTHING
                    """,
                    (approval_id, consumed_at.isoformat(), decision_id),
                )
                connection.commit()
                return cursor.rowcount == 1
            except Exception:
                connection.rollback()
                raise

    def audit_records(self) -> tuple[ApprovalAuditRecord, ...]:
        """Return persisted audit records in sequence order."""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT sequence, decision_id, approval_id, key_id, decision,
                       reason_codes_json, evaluated_at, policy_sha256,
                       previous_hash, record_hash
                FROM approval_decision_audit ORDER BY sequence
                """
            ).fetchall()
        return tuple(
            ApprovalAuditRecord(
                sequence=row[0],
                decision_id=row[1],
                approval_id=row[2],
                key_id=row[3],
                decision=row[4],
                reason_codes=tuple(json.loads(row[5])),
                evaluated_at=row[6],
                policy_sha256=row[7],
                previous_hash=row[8],
                record_hash=row[9],
            )
            for row in rows
        )

    def verify_audit_chain(self) -> bool:
        """Verify the persisted audit sequence and its hash links."""
        return verify_audit_chain(self.audit_records())
