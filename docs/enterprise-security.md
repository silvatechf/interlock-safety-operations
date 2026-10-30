# Kernveil Enterprise Security — prototype scope

## Purpose

The enterprise-security module is a local, non-actuating policy decision prototype. It evaluates synthetic assertions about an authenticated identity, endpoint posture, session state, requested scope, and independent approval. Its motivating scenario is a compromised workforce endpoint attempting to reach privileged resources.

The module is a **Policy Decision Point (PDP)**. It is not a Policy Enforcement Point (PEP), identity provider, endpoint detection and response (EDR) product, privileged access management (PAM) service, or secrets manager. It does not authenticate users, inspect devices, revoke real sessions, issue credentials, or block network/API operations.

## Implemented contracts and behavior

The `sentinel_interlock.security.models` module defines strict, immutable Pydantic contracts for identity, device, session, approval, access request, policy, and decision evidence. Extra fields are rejected and timestamps must be timezone-aware.

Each session assertion is bound to both a subject identifier and a device identifier. The evaluator denies a request when either binding differs from the identity or device assertion in the same request. This prevents accidental cross-composition of otherwise valid synthetic assertions; it does not cryptographically establish that the bindings are authentic.

`evaluate_access()` returns one of three outcomes:

- **ALLOW:** every configured check passed for the supplied assertions.
- **DENY:** at least one explicit policy violation was found, such as an unauthenticated identity, compromised device, revoked/expired or mismatched session, insufficient scope, missing phishing-resistant authentication method, or invalid privileged approval.
- **INDETERMINATE:** no explicit denial was found, but the evidence is insufficient to authorize confidently, for example an untrusted assertion issuer, unknown device posture, or stale device observation.

An explicit denial takes precedence over indeterminate findings. The evaluator is deterministic for a fixed request, policy, and evaluation time, except for the generated decision identifier.

## Property-based verification

`tests/test_security_properties.py` uses Hypothesis to generate variations of session revocation, device posture, evidence age, session subject/device binding, session scopes, privileged action approval, and identity issuer. The properties assert that revoked or mismatched sessions, non-healthy devices, stale evidence, missing scopes, mismatched approvals, and untrusted identity issuers do not produce ALLOW.

These tests exercise decision invariants over generated inputs. They do not verify the authenticity of the assertions, prove complete policy correctness, or establish resistance to attacks against a deployed enforcement path.

## Trust boundaries and limitations

All identity, device, session, and approval attributes are caller-supplied assertions. A string naming an identity issuer or EDR source does not authenticate that source. A `healthy` posture value is not proof of endpoint health. Authentication method labels are not cryptographic proof of MFA. Approval assertions are not signed, and distinct subject identifiers do not prove organizational independence.

The prototype does not validate issuer signatures, token audiences, device certificates, attestation, session revocation feeds, approval signatures, policy governance, or trusted time. It has no persistence, API, distributed state, or external enforcement integration. The session `revoked` flag is an input assertion, not an active revocation mechanism.

A production integration would need authenticated ingress, OIDC/JWT validation with issuer/audience/nonce and key-rotation handling, signed and fresh device posture from an EDR/MDM source, server-side session state, durable policy governance, independently authenticated approval, and a PEP that enforces the PDP decision. Those integrations are not implemented here.

## Running the tests

```shell
pytest tests/test_security_engine.py
ruff check .
mypy src
```

A passing synthetic test demonstrates only the tested decision behavior. It does not establish that an attacker is prevented from accessing a real company resource.
