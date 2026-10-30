"""Enterprise access-risk evaluation prototype.

This package evaluates caller-supplied security assertions. It does not
authenticate identities, inspect endpoints, revoke real sessions, or enforce access.
"""

from .engine import evaluate_access
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
    "ApprovalAssertion", "DeviceAssertion", "DevicePosture", "IdentityAssertion",
    "SessionAssertion", "evaluate_access",
]
