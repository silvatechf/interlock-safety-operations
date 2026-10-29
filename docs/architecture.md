# Architecture

## Decision pipeline

1. A domain adapter validates domain-specific input and produces typed facts.
2. The policy core checks asserted actor authorization, command allow-list, required facts, freshness, and explicit conditions.
3. Decision evidence records policy identifier/version, timestamps, stable reason codes, and evaluated facts.
4. The caller presents the result. The core has no actuation interface.

## Trust boundaries

The evaluator treats command and context as untrusted input. An `actor_id` string is not proof of identity; real authentication and identity binding are outside this reference core. Adapter facts are assertions, not proof of trustworthy sensor origin.

Policy loading, authoring authorization, change review, rollback, signing, and version lifecycle are not implemented.

## Domain separation

The core must remain independent of domain rules. A future railway simulator may model illustrative route/occupancy states; an IT adapter may model simulated maintenance commands and service health. Both remain simulation-only.

## Known gaps

Persistent replay protection and idempotency, cryptographically bound identity, durable/tamper-evident evidence, concurrency and distributed consistency, trusted time, policy governance, independent verification, and domain-specific hazard controls remain unimplemented.
