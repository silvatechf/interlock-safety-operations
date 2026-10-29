# Architecture

## Decision pipeline

1. A domain adapter validates domain-specific input and produces typed facts.
2. The policy model validates declarative structure and the core checks actor allow-list assertions, command allow-list, required facts, context freshness, and explicit equality conditions.
3. An optional `EvaluationSession` serializes evaluations and rejects command IDs already seen during that process lifetime.
4. Decision evidence records policy identifier/version, timestamps, stable reason codes, and evaluated facts.
5. The caller presents the result. The core has no actuation interface.

## Trust boundaries

The evaluator treats command and context as untrusted input. An `actor_id` string is not proof of identity; real authentication and identity binding are outside this reference core. Adapter facts are assertions, not proof of trustworthy sensor origin.

Policy authoring authorization, change review, rollback, signing, and version lifecycle are not implemented.

## Duplicate handling

The optional session guard tracks command IDs in process memory and uses a lock to serialize calls in one process. State is lost on restart and is not shared across processes or hosts. This is not durable idempotency or a distributed replay-protection guarantee.

## Domain separation

The core remains independent of domain rules. Railway and IT adapters use synthetic facts only and do not actuate commands.

## Known gaps

Durable replay defense and idempotency, cryptographically bound identity, durable/tamper-evident evidence, distributed consistency, trusted time, policy governance, independent verification, and domain-specific hazard controls remain unimplemented.
