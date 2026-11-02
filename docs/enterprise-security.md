# Kernveil Enterprise Security — prototype scope

## Purpose

The enterprise-security module is a local, non-actuating policy decision prototype. It evaluates synthetic assertions about an authenticated identity, endpoint posture, session state, requested scope, and independent approval. Its motivating scenario is a compromised workforce endpoint attempting to reach privileged resources.

The module is a **Policy Decision Point (PDP)**. It is not a Policy Enforcement Point (PEP), identity provider, endpoint detection and response (EDR) product, privileged access management (PAM) service, or secrets manager. It does not authenticate users, inspect devices, revoke real sessions, issue credentials, or block network/API operations.

## Implemented contracts and behavior

The `sentinel_interlock.security.models` module defines strict, immutable Pydantic contracts for identity, device, session, approval, access request, policy, and decision evidence. Extra fields are rejected and timestamps must be timezone-aware.

Each session assertion is bound to a subject identifier, a device identifier, and a set of exact `SessionGrant` pairs. Every grant contains one action and one resource identifier. The evaluator requires an exact pair match; there are no wildcard, prefix, or pattern semantics. Resource identifiers are opaque, case-sensitive strings. These checks are consistency checks over caller-supplied values, not cryptographic proof of authenticity.

`evaluate_access()` returns ALLOW, DENY, or INDETERMINATE for the supplied assertions. Explicit denials take precedence over indeterminate findings. Approval timestamps in the future produce `APPROVAL_NOT_YET_VALID`; stale or expired approvals produce `APPROVAL_EXPIRED`. Expiry boundaries are exclusive: an approval or session is not valid when `evaluated_at >= expires_at`.

## Signed approvals and key lifecycle

The secure `evaluate_and_consume_approval()` workflow requires an `ApprovalVerifier`. The Ed25519 implementation verifies a canonical payload covering the approval ID, approver subject, action, resource, approval and expiry timestamps, and key ID.

Each locally configured `ApprovalVerificationKey` binds a key ID to one approver subject and defines:
- `valid_from`: inclusive activation instant;
- `valid_until`: optional exclusive expiry instant;
- `revoked_at`: optional instant from which the key is rejected.

The verifier checks `valid_from <= evaluated_at < valid_until` when an end is configured, and rejects the key when `evaluated_at >= revoked_at`. Multiple key IDs can coexist in the local registry, allowing an explicit overlap during rotation. The registry is immutable for each verifier instance: updating it requires constructing and deploying a new verifier configuration.

The evaluation instant is supplied by the caller through the orchestration function. These checks therefore enforce configured boundaries against that supplied instant; they do not provide a trusted clock, trusted timestamping, automatic key distribution, or immediate fleet-wide revocation. Key provisioning and private-key custody remain external responsibilities. A valid signature proves possession of the corresponding private key and integrity of the signed claims; it does not independently prove human identity or organizational independence.

## Replay protection and transactional audit

The pure `evaluate_access()` function remains stateless and does not verify signatures. The secure orchestration verifies the signature and key lifecycle before attempting to consume the approval identifier.

`SQLiteApprovalStore` persists approval consumption and decision audit records in the same SQLite database. For an accepted signed approval, the approval identifier and ALLOW audit record are committed in one transaction. If the identifier was already consumed, the same transaction records a DENY with `APPROVAL_ALREADY_CONSUMED`. Policy denials and signature failures are also recorded without consuming the approval.

Audit records contain the decision reference, approval ID, key ID, outcome, reason codes, evaluation timestamp, and policy fingerprint. Subject identifiers, resource identifiers, raw assertions, signatures, and private keys are intentionally excluded from this audit projection. The records are linked with SHA-256 hashes and can be verified in sequence using `verify_audit_chain()` or `SQLiteApprovalStore.verify_audit_chain()`.

The hash chain detects modification, reordering, and removal of intermediate records relative to the retained sequence. It does **not** prevent a privileged database writer from rewriting the entire database and recomputing the chain, nor can it detect deletion of a valid suffix without an independently retained checkpoint. This implementation has no external anchoring, digital signatures, trusted timestamping, retention controls, or immutable remote storage. Audit write failures raise an exception; callers must treat the decision workflow as failed rather than assume a decision was durably recorded.

The older `consume()` method remains available for replay-only compatibility, but it does not create an audit record. Decision workflows must use `evaluate_and_consume_approval()`.

## Trust boundaries and remaining production work

All identity, device, session, and approval attributes remain caller-supplied assertions. The prototype does not validate identity-provider signatures, token audiences, device certificates, attestation, session revocation feeds, or policy governance. It has no general API, distributed state, or external enforcement integration.

A production integration would need authenticated ingress, OIDC/JWT validation with issuer/audience/nonce and key-rotation handling, signed and fresh device posture from an EDR/MDM source, server-side session state, durable policy governance, independently authenticated approval, trusted time, secure key provisioning and distribution, and a PEP that enforces the PDP decision. Those integrations are not implemented here.

## Running the tests

```shell
pytest tests/test_security_approval_replay.py tests/test_security_approval_audit.py
ruff check .
mypy src
```

A passing synthetic test demonstrates only the tested decision behavior. It does not establish that an attacker is prevented from accessing a real company resource.
