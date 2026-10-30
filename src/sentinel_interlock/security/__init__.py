"""Enterprise access-risk evaluation prototype.

This package evaluates caller-supplied security assertions. It does not
authenticate identities, inspect endpoints, revoke real sessions, or enforce access.
"""

from .approval_store import SQLiteApprovalStore
from .approval_signatures import (
    ApprovalVerificationKey,
    Ed25519ApprovalVerifier,
    approval_signing_payload,
)
from .engine import evaluate_access, evaluate_and_consume_approval
from .models import (
    AccessDecision,
    AccessEvidence,
    AccessPolicy,
    AccessRequest,
    ApprovalAssertion,
    DeviceAssertion,
    DevicePosture,
    IdentityAssertion,
    SessionAssertion,
)

__all__ = [
    "AccessDecision", "AccessEvidence", "AccessPolicy", "AccessRequest",
    "ApprovalAssertion",
    "ApprovalVerificationKey",
    "Ed25519ApprovalVerifier",
    "approval_signing_payload",
    "DeviceAssertion",
    "DevicePosture",
    "IdentityAssertion",
    "SQLiteApprovalStore",
    "SessionAssertion",
    "evaluate_access",
    "evaluate_and_consume_approval",
]
