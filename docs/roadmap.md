# Roadmap

## Milestone 0 — Foundation
- [x] Establish scope, non-goals, safety boundary, and threat model.
- [x] Add a small policy evaluator and deterministic tests.
- [x] Verify CI execution and resolve discovered issues.

## Milestone 1 — Core contracts
- [x] Add initial property-based tests for deny-by-default behavior.
- [x] Validate malformed policy conditions and blank policy entries at construction.
- [x] Add process-local duplicate-command detection with explicit lifecycle limits.
- [x] Define versioned evidence serialization.
- [x] Reject ambiguous, non-standard, and oversized evidence JSON.
- [x] Add an in-memory SHA-256 hash chain with tamper-detection tests and documented limits.

## Milestone 2 — Initial simulators
- [x] Railway-inspired simulator using synthetic state only.
- [x] IT operations adapter for simulated maintenance/restart commands.
- [x] Document scenario assumptions, adversarial cases, and limitations.
- [x] Keep all scenarios free of physical-world integration and actuation.

## Milestone 3 — Engineering assurance
- [x] Expand state-transition models and invariants.
- [ ] Add fault injection and broader fuzz/property tests.
- [x] Add secret scanning and review CI action pinning.
- [x] Trace risks to tests and architecture decisions.
- [x] Repository-level review of public claims and scope (self-review; not an external independent assessment).

## Milestone 4 — Kernveil Resilience Lab (planned)
- [ ] Define a versioned synthetic event envelope and trust assumptions.
- [ ] Specify source claims, integrity, freshness, sequence, correlation, and clock uncertainty.
- [ ] Implement deterministic event validation with stable reason codes.
- [ ] Add reproducible fault injection for loss, delay, duplication, reordering, corruption, outage, and clock skew.
- [ ] Connect validated synthetic context to the existing policy engine without adding actuation.
- [ ] Generate local scenario reports with detection metrics and explicit limitations.

## Milestone 5 — Road-disruption simulator (first new domain)
- [ ] Model synthetic traffic-light outage, collision, road closure, debris/hazard, and contradictory reports.
- [ ] Distinguish fresh, stale, duplicated, correlated, untrusted, and indeterminate reports.
- [ ] Demonstrate advisory classification without right-of-way, route-control, or driver-instruction decisions.
- [ ] Add labelled fixtures and reproducible tests for each scenario.

## Milestone 6 — Additional transport adapters
- [ ] Reuse the domain-neutral contracts for a railway-inspired resilience adapter.
- [ ] Evaluate maritime and aviation adapters only after separate domain-specific threat models and scope reviews.
- [ ] Keep all domain adapters synthetic, non-actuating, and explicit about their assumptions.

## Milestone 7 — Evidence maturity and independent review
- [ ] Evaluate durable append-only storage, crash consistency, and concurrency behavior.
- [ ] Design signed evidence checkpoints or external anchors, including key custody and recovery.
- [ ] Test final-suffix truncation and whole-chain rewrite detection against independently retained checkpoints.
- [ ] Request independent architecture and threat-model review.
- [ ] Seek qualified domain review before making domain-specific assurance claims.

## Deferred by design
- Broader fault injection and fuzz/property tests remain planned work; they are not represented as completed assurance.
- External independent assessment has not been performed. The completed scope review is a repository-level self-review only.
- Live road, railway, aviation, maritime, industrial, or production-system integration is outside this portfolio prototype.

## Release gate
A passing pipeline is a quality signal, not a safety case. Do not describe this project as production-ready, certified, compliant, or suitable for operational control. Do not claim zero risk or complete prevention of communication and technology failures.
