"""Ed25519 verification for privileged approval assertions.

Private-key custody and approval issuance belong to a trusted external issuer.
This module contains public-key verification only.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import ApprovalAssertion


@dataclass(frozen=True, slots=True)
class ApprovalVerificationKey:
    """A trusted Ed25519 public key bound to one approver subject."""

    approver_subject_id: str
    public_key: bytes


class ApprovalVerifier(Protocol):
    """Signature-verification boundary used by the privileged-access workflow."""

    def verify(self, approval: ApprovalAssertion) -> bool: ...


def approval_signing_payload(approval: ApprovalAssertion) -> bytes:
    """Serialize all security-relevant approval claims into canonical bytes."""
    payload = {
        "approval_id": approval.approval_id,
        "approver_subject_id": approval.approver_subject_id,
        "action": approval.action,
        "resource": approval.resource,
        "approved_at": approval.approved_at.astimezone(UTC).isoformat(
            timespec="microseconds"
        ),
        "expires_at": approval.expires_at.astimezone(UTC).isoformat(
            timespec="microseconds"
        ),
        "key_id": approval.key_id,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class Ed25519ApprovalVerifier:
    """Verify approval claims against an explicit trusted public-key registry."""

    def __init__(self, trusted_keys: Mapping[str, ApprovalVerificationKey]) -> None:
        if not trusted_keys:
            raise ValueError("at least one trusted approval key is required")
        normalized: dict[str, ApprovalVerificationKey] = {}
        for key_id, key in trusted_keys.items():
            if not key_id.strip():
                raise ValueError("key identifiers must not be blank")
            if len(key.public_key) != 32:
                raise ValueError("Ed25519 public keys must contain exactly 32 bytes")
            if not key.approver_subject_id.strip():
                raise ValueError("trusted approver subject identifiers must not be blank")
            normalized[key_id] = key
        self._trusted_keys = normalized

    def verify(self, approval: ApprovalAssertion) -> bool:
        """Return False for unknown keys, mismatched subjects, or invalid signatures."""
        if approval.key_id is None or approval.signature is None:
            return False
        trusted = self._trusted_keys.get(approval.key_id)
        if trusted is None or trusted.approver_subject_id != approval.approver_subject_id:
            return False

        try:
            encoded = approval.signature.encode("ascii")
            signature = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
            if base64.urlsafe_b64encode(signature).rstrip(b"=") != encoded:
                return False
            Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(
                signature, approval_signing_payload(approval)
            )
        except (UnicodeEncodeError, ValueError, binascii.Error, InvalidSignature):
            return False
        return True
