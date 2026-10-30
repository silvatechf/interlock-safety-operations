"""Local durable, atomic consumption of synthetic approval identifiers."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Protocol


class ApprovalStore(Protocol):
    """Persistence boundary required by the approval-consumption workflow."""

    def consume(
        self, approval_id: str, *, consumed_at: datetime, decision_id: str
    ) -> bool: ...


class SQLiteApprovalStore:
    """Consume approval identifiers once within one SQLite database."""

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

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database, timeout=self._timeout_seconds, isolation_level=None
        )
        connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
        return connection

    def consume(
        self,
        approval_id: str,
        *,
        consumed_at: datetime,
        decision_id: str,
    ) -> bool:
        """Atomically claim an identifier; return False when it was already used."""
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
