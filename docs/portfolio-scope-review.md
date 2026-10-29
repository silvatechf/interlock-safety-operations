# Portfolio scope review

## Outcome

The repository is appropriately scoped as a local-first portfolio reference for policy evaluation over synthetic scenarios. It is not an operational control product, safety case, certified component, or production-ready system.

## Checks performed

- Compared the README's headline and summary with the implemented architecture and documented limitations.
- Confirmed that railway-inspired and IT examples use synthetic inputs and have no external actuation.
- Checked that actor identifiers are not presented as authenticated identity, supplied facts are not presented as trusted sensor data, and process-local replay handling is not described as durable.
- Distinguished strict evidence serialization from the separate SHA-256 evidence chain: the chain is tamper-evident only relative to an independently retained expected chain, and it is neither authenticated nor durable.
- Checked the decision status/reason-code invariant: ALLOW has no denial reasons; DENY has at least one.
- Checked the risk traceability matrix against named tests and retained residual limitations.
- Checked that the roadmap distinguishes completed work from deferred fault-injection/property expansion.
- Confirmed that CI is a software-quality signal, not evidence of operational safety.

## Remaining limitations

- No real authentication or trusted sensor provenance.
- No trusted clock, durable replay protection, or distributed consistency.
- Evidence chain is in-memory only, unauthenticated, and vulnerable to whole-chain recomputation and undetected suffix truncation without an external checkpoint.
- No policy signing, governance, rollback, or production hardening.
- No external independent assessment has been performed.
- Broader fault injection and fuzz/property tests are deferred; current tests cover only their named behaviors.

## Portfolio wording

Recommended description:

> Kernveil is a local-first Python reference project that evaluates explicit policies against synthetic operational scenarios, returns explainable decisions and evidence, and demonstrates deny-by-default behavior through automated tests. It does not execute commands or control real infrastructure.

Avoid describing the project as a railway interlocking, safety controller, certified, compliant, production-ready, or safe for operational use.

## Review status

This is a repository-level self-review of wording, traceability, and stated boundaries. It is not an external independent review, formal verification, certification, or safety assessment.
