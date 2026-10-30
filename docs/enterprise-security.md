# Kernveil Enterprise Security — prototype scope

## Purpose

The enterprise-security module is a local, non-actuating policy decision prototype. It evaluates synthetic assertions about an authenticated identity, endpoint posture, session state, requested scope, and independent approval. Its motivating scenario is a compromised workforce endpoint attempting to reach privileged resources.

The module is a **Policy Decision Point (PDP)**. It is not a Policy Enforcement Point (PEP), identity provider, endpoint detection and response (EDR) product, privileged access management (PAM) service, or secrets manager. It does not authenticate users, inspect devices, revoke real sessions, issue credentials, or block network/API operations.

## Implemented contracts and behavior

The `sentinel_interlock.security.models` module defines strict, immutable Pydantic contracts for identity, device, session, approval, access request, policy, and decision evidence. Extra fields are rejected and timestamps must be timezone-aware.

Each session assertion is bound to a subject identifier, a device identifier, and a set of exact `SessionGrant` pairs. Every grant contains one action and one resource identifier. The evaluator requires an exact pair match: granting `secrets.read` on `vault://production/team-a` does not grant the same action on `vault://development/team-a`. There are no wildcard, prefix, or pattern semantics. Resource identifiers are opaque, case-sensitive strings; the evaluator does not canonicalize or interpret their URI syntax. Subject/device binding and grant membership are consistency checks over caller-supplied values, not cryptographic proof of authenticity.

`evaluate_access()` returns one of three outcomes:

- **ALLOW:** every configured check passed for the supplied assertions.
- **DENY:** at least one explicit policy violation was found, such as an unauthenticated identity, compromised device, revoked/expired or mismatched session, insufficient scope, missing phishing-resistant authentication method, or invalid privileged approval.
- **INDETERMINATE:** no explicit denial was found, but the evidence is insufficient to authorize confidently, for example an untrusted assertion issuer, unknown device posture, or stale device observation.

An explicit denial takes precedence over indeterminate findings. Approval timestamps in the future produce the distinct `APPROVAL_NOT_YET_VALID` reason; approvals older than the configured maximum age or expiring at the evaluation instant produce `APPROVAL_EXPIRED`. Expiry boundaries are exclusive: a session or approval is not valid when `evaluated_at >= expires_at`. The evaluator is deterministic for a fixed request, policy, and evaluation time, except for the generated decision identifier.

## Policy fingerprint and evidence

Every access decision includes a `policy_sha256` value: a SHA-256 fingerprint of the effective policy configuration used for that evaluation. The fingerprint includes the policy identifier and version, sorted trust and requirement sets, and all configured freshness limits. Sorting set-valued fields makes the fingerprint independent of their iteration order.

The fingerprint makes configuration drift visible even when an operator accidentally reuses a policy version label. It is a content identifier, **not a digital signature**: it does not authenticate who created or approved the policy, prevent replacement, or prove that the policy was deployed. The policy object and its fingerprint remain caller-controlled inputs in this local prototype.

## Property-based verification

`tests/test_security_properties.py` uses Hypothesis to generate variations of session revocation, device posture, evidence age, session subject/device binding, exact session action/resource grants, privileged action approval, and identity issuer. The properties assert that revoked or mismatched sessions, non-healthy devices, stale evidence, missing or resource-mismatched grants, mismatched approvals, and untrusted identity issuers do not produce ALLOW.

`tests/test_security_engine.py` also verifies that equivalent set configurations produce the same policy fingerprint and that a changed effective configuration produces a different fingerprint even when the version label is unchanged. `tests/test_security_approval_boundaries.py` verifies approval freshness boundaries, future-dated approvals, exact expiry behavior, resource binding, and denial precedence.

These tests exercise decision invariants over generated inputs. They do not verify the authenticity of the assertions, prove complete policy correctness, or establish resistance to attacks against a deployed enforcement path.

## Trust boundaries and limitations

All identity, device, session, and approval attributes are caller-supplied assertions. A string naming an identity issuer or EDR source does not authenticate that source. A `healthy` posture value is not proof of endpoint health. Authentication method labels are not cryptographic proof of MFA. Approval assertions are not signed, and distinct subject identifiers do not prove organizational independence.

The prototype does not validate issuer signatures, token audiences, device certificates, attestation, session revocation feeds, approval signatures, policy governance, or trusted time. It has no persistence, API, distributed state, or external enforcement integration. The session `revoked` flag is an input assertion, not an active revocation mechanism. Approval assertions carry a caller-supplied `approval_id`. The pure `evaluate_access()` function remains stateless and can evaluate the same approval repeatedly. The optional `evaluate_and_consume_approval()` orchestration function first runs the complete policy evaluation and only attempts consumption after an `ALLOW` for a privileged action. `SQLiteApprovalStore` records consumed identifiers using a primary key and an atomic SQLite write transaction; a repeated identifier returns `DENY` with `APPROVAL_ALREADY_CONSUMED`. Failed or indeterminate policy evaluations do not consume an approval. The local store survives process restarts when backed by a file, and its uniqueness constraint serializes competing consumers of the same identifier within that database. This is a local single-database control, not distributed replay protection. The approval identifier remains caller-supplied and unsigned: an attacker able to forge an approval or choose a fresh identifier can bypass the intended identity of the approval. Cryptographic authenticity, trusted approval issuance, and distributed storage are not implemented.

A production integration would need authenticated ingress, OIDC/JWT validation with issuer/audience/nonce and key-rotation handling, signed and fresh device posture from an EDR/MDM source, server-side session state, durable policy governance, independently authenticated approval, and a PEP that enforces the PDP decision. Those integrations are not implemented here.

## Running the tests

```shell
pytest tests/test_security_engine.py
ruff check .
mypy src
```

A passing synthetic test demonstrates only the tested decision behavior. It does not establish that an attacker is prevented from accessing a real company resource.
