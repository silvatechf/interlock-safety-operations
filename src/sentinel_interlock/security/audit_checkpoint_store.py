"""Local file persistence for portable approval-audit checkpoints.

A file on the same host is a recovery convenience, not an independent trust
domain or external tamper-protection boundary.
"""

from __future__ import annotations

import json
import os
import tempfile
from enum import Enum
from pathlib import Path
from typing import Protocol

from .approval_audit import (
    AUDIT_CHAIN_SCHEMA_VERSION,
    ApprovalAuditCheckpoint,
    ApprovalAuditRecord,
    verify_audit_checkpoint,
)


class ApprovalAuditCheckpointStore(Protocol):
    """Minimal persistence contract for one independently retained checkpoint."""

    def load(self) -> ApprovalAuditCheckpoint | None: ...

    def save(self, checkpoint: ApprovalAuditCheckpoint) -> None: ...


class JsonFileApprovalAuditCheckpointStore:
    """Persist a checkpoint as strict JSON using atomic same-directory replacement.

    The adapter is intentionally local and single-writer. File permissions are
    best-effort on platforms that support POSIX mode bits. Callers must protect
    the parent directory and coordinate concurrent writers themselves.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @staticmethod
    def _validate(checkpoint: ApprovalAuditCheckpoint) -> None:
        if not isinstance(checkpoint, ApprovalAuditCheckpoint):
            raise TypeError("checkpoint must be an ApprovalAuditCheckpoint")
        if type(checkpoint.schema_version) is not int:
            raise ValueError("invalid checkpoint schema_version")
        if checkpoint.schema_version != AUDIT_CHAIN_SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint schema_version")
        if type(checkpoint.sequence) is not int or checkpoint.sequence < 0:
            raise ValueError("invalid checkpoint sequence")
        if (
            not isinstance(checkpoint.record_hash, str)
            or len(checkpoint.record_hash) != 64
            or any(char not in "0123456789abcdef" for char in checkpoint.record_hash)
        ):
            raise ValueError("invalid checkpoint record_hash")

    def load(self) -> ApprovalAuditCheckpoint | None:
        """Load a checkpoint; return None only when the file does not exist."""
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except UnicodeDecodeError as exc:
            raise ValueError("checkpoint file is not valid UTF-8 JSON") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("checkpoint file is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "sequence", "record_hash"
        }:
            raise ValueError("checkpoint file has an invalid structure")
        checkpoint = ApprovalAuditCheckpoint(
            schema_version=payload["schema_version"],
            sequence=payload["sequence"],
            record_hash=payload["record_hash"],
        )
        self._validate(checkpoint)
        return checkpoint

    def save(self, checkpoint: ApprovalAuditCheckpoint) -> None:
        """Atomically replace the checkpoint file after validating its structure."""
        self._validate(checkpoint)
        if not self._path.parent.is_dir():
            raise FileNotFoundError(f"checkpoint directory does not exist: {self._path.parent}")

        payload = json.dumps(
            {
                "schema_version": checkpoint.schema_version,
                "sequence": checkpoint.sequence,
                "record_hash": checkpoint.record_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"

        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = temporary.name
                temporary.write(payload)
                temporary.flush()
                os.fsync(temporary.fileno())
            try:
                os.chmod(temporary_path, 0o600)
            except OSError:
                # Windows and some filesystems do not expose POSIX permissions.
                pass
            os.replace(temporary_path, self._path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass


class AuditCheckpointStatus(str, Enum):
    """Result of comparing a persisted checkpoint with an audit snapshot."""

    MISSING = "missing"
    VALID = "valid"
    INVALID = "invalid"


def verify_stored_audit_checkpoint(
    records: object,
    store: ApprovalAuditCheckpointStore,
) -> AuditCheckpointStatus:
    """Load and verify a retained checkpoint against one audit-chain snapshot.

    Missing checkpoints and mismatches are explicit outcomes. Storage I/O and
    malformed-file errors intentionally propagate so callers cannot mistake
    an unavailable or corrupt checkpoint for a valid chain.
    """
    checkpoint = store.load()
    if checkpoint is None:
        return AuditCheckpointStatus.MISSING
    if not verify_audit_checkpoint(records, checkpoint):
        return AuditCheckpointStatus.INVALID
    return AuditCheckpointStatus.VALID
