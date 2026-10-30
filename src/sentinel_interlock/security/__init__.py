"""Enterprise access-risk evaluation prototype.

This package evaluates caller-supplied security assertions. It does not
authenticate identities, inspect endpoints, revoke real sessions, or enforce access.
"""

from .engine import evaluate_access, evaluate_and_consume_approval
from .approval_store import SQLiteApprovalStore
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
    "ApprovalAssertion", "SQLiteApprovalStore", "DeviceAssertion", "DevicePosture", "IdentityAssertion",
    "SessionAssertion", "evaluate_access", "evaluate_and_consume_approval",
]
