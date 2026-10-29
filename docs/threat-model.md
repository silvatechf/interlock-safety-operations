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
- Operators interpreting a demo as a certified safety control.

## Current mitigations

- Pydantic validation with extra fields forbidden.
- Explicit allow-lists and deny-by-default evaluation.
- Context freshness check and future timestamp rejection.
- Stable reason codes and structured evidence.
- No command execution or external actuation.
- Explicitly documented safety boundary.

## Important gaps

No real identity authentication, trusted sensor provenance, persistent replay defense, cryptographic evidence integrity, durable storage, concurrency controls, key management, or production hardening are implemented. The in-memory ledger is not tamper-evident; timestamp validation does not make a clock trustworthy.

## Abuse cases for future tests

Duplicate command IDs across restarts; unauthorized policy updates; conflicting adapter facts; huge payloads; clock rollback; failure between decision and persistence; and attempted actuation from the evaluator.

This MVP is suitable only for local experiments and portfolio demonstrations.
