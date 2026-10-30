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

The verifier checks `valid_from <= evaluated_at < valid_until` when an end is configured, and rejects the key when `evaluated_at >= revoked_at`. Multiple key IDs can coexist in the local registry, allowing an explicit overlap during rotation. A retired key can be removed from the registry; a compromised key can be revoked by setting its revocation instant. The registry is immutable for each verifier instance: updating it requires constructing and deploying a new verifier configuration.

The evaluation instant is supplied by the caller through the orchestration function. These checks therefore enforce configured boundaries against that supplied instant; they do not provide a trusted clock, trusted timestamping, automatic key distribution, or immediate fleet-wide revocation. Key provisioning and private-key custody remain external responsibilities. A valid signature proves possession of the corresponding private key and integrity of the signed claims; it does not independently prove human identity or organizational independence.

## Replay protection and trust boundaries

The pure `evaluate_access()` function remains stateless and does not verify signatures. The secure orchestration verifies the signature and key lifecycle before consuming the approval identifier. `SQLiteApprovalStore` records consumed identifiers with a primary key and atomic SQLite write transaction. This is local single-database replay protection, not distributed coordination.

All identity, device, session, and approval attributes remain caller-supplied assertions. The prototype does not validate identity-provider signatures, token audiences, device certificates, attestation, session revocation feeds, or policy governance. It has no general API, distributed state, or external enforcement integration.

A production integration would need authenticated ingress, OIDC/JWT validation with issuer/audience/nonce and key-rotation handling, signed and fresh device posture from an EDR/MDM source, server-side session state, durable policy governance, independently authenticated approval, trusted time, secure key provisioning and distribution, and a PEP that enforces the PDP decision. Those integrations are not implemented here.

## Running the tests

```shell
pytest tests/test_security_approval_replay.py
ruff check .
mypy src
```

A passing synthetic test demonstrates only the tested decision behavior. It does not establish that an attacker is prevented from accessing a real company resource.
