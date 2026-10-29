# Safety boundary and hazard notes

## Intended use

Demonstrate explicit policy evaluation, fail-closed outcomes, structured decision evidence, and testing. The railway-inspired case is a simulator only.

## Prohibited interpretation

An `allow` decision means only that the implemented demo policy's checks passed for supplied data. It does not prove a physical operation safe, data authentic, or a railway route available.

Do not connect this code to signalling, interlocking, train control, braking, dispatch, PLCs, live telemetry, production maintenance, or operational control paths.

## Illustrative hazards

| Hazard | Example cause | Boundary / mitigation |
|---|---|---|
| False allow | Missing or fabricated context | Require declared facts; never trust demo facts as sensor truth |
| Stale basis | Delayed context or clock error | Check context age and future timestamps; clock trust remains unresolved |
| Unauthorized command | Forged actor ID | Allow-list only; real authentication is not implemented |
| Duplicate command | Replay or retry | Optional session guard denies duplicate IDs within one process; no durable idempotency |
| Evidence loss | Process restart | In-memory ledger only |
| Domain mismatch | Generic check mistaken for a railway rule | Domain constraints stay in simulation adapters |
| Misuse as safety component | Demo connected to live systems | Explicit warnings and no actuation API |

## Assurance statement

No safety integrity level, standards conformity, certification, or operational suitability is claimed. Any future safety-related application requires domain-specific hazard analysis, verified requirements, validated interfaces and lifecycle assurance, independent review, and qualified safety specialists.
