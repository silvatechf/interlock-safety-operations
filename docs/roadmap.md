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
- [ ] Add broader fault injection and fuzz/property tests.
- [x] Add secret scanning and review CI action pinning.
- [x] Trace risks to tests and architecture decisions.
- [x] Repository-level review of public claims and scope (self-review; not an external independent assessment).

## Milestone 4 — Event validation foundation
- [x] Define a versioned synthetic event envelope.
- [x] Implement source allow-list, payload digest consistency, freshness, expiry, duplicate ID, and sequence checks.
- [x] Return VALID, REJECTED, and INDETERMINATE outcomes with stable reason codes.
- [x] Add deterministic tests for expected validation outcomes.
- [ ] Add property-based and fuzz testing for event envelopes and payload boundaries.
- [ ] Define durable source identity, trust lifecycle, and replay-state persistence.

## Milestone 5 — Road-disruption simulator (first new domain)
- [x] Model synthetic traffic-signal outage, hazard reports, and contradictory reports.\n- [ ] Extend fixtures to collision and road-closure scenarios.
- [x] Distinguish fresh, stale, duplicated, untrusted, and indeterminate reports.\n- [ ] Add semantic incident correlation and independent-source provenance assumptions.
- [ ] Demonstrate advisory classification without right-of-way, route-control, or driver-instruction decisions.
- [x] Add labelled fixtures and reproducible tests for the initial scenario suite.\n- [ ] Expand regression fixtures to collision, road closure, and recovery cases.

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

## Milestone 6 — Enterprise access decision foundation
- [x] Define strict Pydantic contracts for identity, device posture, session, approval, access request, policy, and evidence.
- [x] Implement deterministic ALLOW, DENY, and INDETERMINATE access decisions.
- [x] Evaluate authentication-method assertions, device posture/source/freshness, session expiry/revocation/scope, and independent approval assertions.
- [x] Add deterministic tests for compromised-endpoint and privileged-access cases.
- [x] Add Hypothesis tests for revocation, device posture, freshness, session scope, approval matching, and trusted issuer invariants.
- [ ] Add signed identity/device/approval assertion verification and explicit trust lifecycle.
- [ ] Define policy version governance and safe rollback.

## Milestone 7 — Enforcement and integrations
- [ ] Design a minimal PEP integration boundary and deny-by-default behavior.
- [ ] Evaluate OIDC/JWT verification, key rotation, and real identity-provider integration.
- [ ] Evaluate signed device posture from an EDR/MDM provider.
- [ ] Evaluate server-side revocation state and durable storage.
- [ ] Add integration tests using isolated local test services.
- [ ] Do not claim real protection until an end-to-end enforcement path is independently tested.

## Deferred by design
- Broader fault injection and fuzz/property tests remain planned work; they are not represented as completed assurance.
- External independent assessment has not been performed. The completed scope review is a repository-level self-review only.
- Live road, railway, aviation, maritime, industrial, or production-system integration is outside this portfolio prototype.

## Release gate
A passing pipeline is a quality signal, not a safety case. Do not describe this project as production-ready, certified, compliant, or suitable for operational control. Do not claim zero risk or complete prevention of communication and technology failures.
