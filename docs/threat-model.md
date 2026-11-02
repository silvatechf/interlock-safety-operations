# Threat model

## Assets

- Integrity of policy decisions.
- Correctness and freshness of policy facts.
- Authorization policy and version history.
- Decision evidence.
- Separation between simulation and live operations.

## Threats and failure sources

- Unauthenticated or unauthorized callers.
- Malformed, missing, replayed, duplicated, or out-of-order commands.
- Stale, future-dated, contradictory, or fabricated facts.
- Misconfigured or malicious policy changes.
- Clock drift, partial failures, process restarts, concurrency, or evidence loss.
- Evidence payload modification, record removal, reordering, or chain truncation.
- Operators interpreting a demo as a certified safety control.

## Current mitigations

- Versioned synthetic event envelope with timezone-aware timestamps.
- Caller-configured source allow-list, freshness/expiry, duplicate ID, sequence, and canonical payload digest checks.
- Explicit VALID, REJECTED, and INDETERMINATE event outcomes with stable reason codes.

- Pydantic validation with extra fields forbidden.
- Strict evidence JSON parsing: duplicate properties, non-standard numeric constants, and payloads above 1 MiB are rejected.
- Explicit allow-lists and deny-by-default evaluation.
- Context freshness check and future timestamp rejection.
- Stable reason codes and structured evidence.
- In-memory SHA-256 hash-linked evidence sequence with verification tests for edits, middle removal, reordering, and broken links.
- No command execution or external actuation.
- Explicitly documented safety boundary.

## Important gaps

No real identity authentication, trusted sensor provenance, persistent replay defense, durable evidence storage, trusted timestamps, key management, signed or externally anchored evidence, distributed concurrency controls, or production hardening are implemented. The SHA-256 chain detects changes relative to a retained chain, but does not authenticate its author and can be fully recomputed by an attacker who can rewrite all records. Truncation of a final suffix is not detectable without an independently retained checkpoint or external anchor. The in-memory ledger remains non-durable.

## Abuse cases for future tests

Duplicate command IDs across restarts; unauthorized policy updates; conflicting adapter facts; huge payloads; clock rollback; failure between decision and persistence; whole-chain rewrite; final-suffix truncation; and attempted actuation from the evaluator.

This project is suitable only for local experiments and portfolio demonstrations.
