# Kernveil Resilience Lab — prototype direction

## Purpose

Kernveil Resilience Lab is a local-first research and portfolio prototype for evaluating the trustworthiness of synthetic operational events and testing resilience under explicitly modelled failures.

The product is **domain-agnostic at its core**. Transportation is the first application family, with road incidents and infrastructure disruption as the first demonstrator. Railway, aviation, and maritime scenarios can follow as separate adapters. The same validation primitives may later apply to other critical or high-availability environments, but each domain requires its own threat model, semantics, risk analysis, and qualified review.

The central question is: given an event, its declared source, timing, integrity metadata, and surrounding synthetic context, can Kernveil identify what is valid, stale, duplicated, contradictory, or uncertain, explain the result, and avoid presenting uncertainty as fact?

This is a design proposal. The current implementation status is called out explicitly below.

## Product boundary

Kernveil is an independent event-validation and resilience-testing layer in a simulation environment. It is not a navigation service, traffic-management platform, dispatch system, certified safety component, or replacement for domain operators and procedures.

The prototype will ingest synthetic events and simulated states; validate structure, source claims, integrity metadata, sequence, freshness, and consistency; evaluate explicit policies; inject selected faults; and produce repeatable evidence and reports.

It will not connect to live road infrastructure, traffic-light controllers, vehicles, aircraft, vessels, railway networks, telemetry, signalling, dispatch, PLC/SCADA, braking, or production systems. It will not send commands, actuate equipment, direct vehicles, or make operational decisions. It will not claim zero risk, complete attack prevention, certification, or regulatory conformity.

## Proposed logical architecture

```mermaid
flowchart TD
    A["Synthetic event producers / scenario fixtures"] --> B["Event ingress and schema validation"]
    B --> C["Trust, integrity and freshness checks"]
    C --> D["Correlation and anomaly rules"]
    D --> E["Domain adapter and context model"]
    E --> F["Kernveil policy evaluation core"]
    G["Deterministic fault injector"] --> A
    G --> B
    G --> C
    G --> D
    G --> E
    F --> H["Explainable advisory / review outcome"]
    H --> I["Local evidence and scenario report"]
```

This is conceptual, not a deployed operational architecture. The current policy engine and event validator are the starting foundation. Correlation, fault injection, domain adapters beyond existing examples, and the inspection interface remain future work.

## Implemented foundation

The new `sentinel_interlock.events` module currently provides:
- a versioned, validated synthetic event envelope;
- timezone-aware event timestamps and expiry consistency;
- caller-supplied source allow-list checks;
- deterministic payload SHA-256 calculation over canonical JSON;
- event freshness and expiry checks;
- duplicate event ID and non-advancing sequence checks against caller-supplied state;
- explicit VALID, REJECTED, and INDETERMINATE outcomes with stable reason codes;
- rejection of malformed/non-JSON and oversized payloads.

These are bounded validation checks, not authenticated source identity or trusted sensor provenance. The validator is stateless: callers supply replay state, and the module does not persist or update it. A digest is not a signature. The module does not yet correlate reports, establish independent corroboration, inject faults, or provide road/rail/aviation/maritime operational semantics.

## Proposed components

### Synthetic event envelope

Implemented as `OperationalEvent` in `src/sentinel_interlock/events.py`. It contains schema version, event ID, claimed source ID, event type, sequence, occurrence and optional expiry timestamps, payload, and optional payload digest.

A claimed source identifier is not authenticated identity. A digest detects content changes only when the expected digest is trusted; it does not authenticate the sender. Signature verification, if introduced, must use test-only keys and an explicit key lifecycle.

### Trust and freshness validator

Implemented as `validate_event()`. It evaluates schema validity, source allow-list, event age and expiry, sequence continuity, duplicate IDs, and payload digest consistency. Replay state and trust configuration are caller-supplied and process-local unless a future persistence layer is added.

Time checks must model clock uncertainty rather than assuming timestamps are inherently trustworthy. The current implementation marks events too far in the future as INDETERMINATE; stale or expired events are REJECTED.

### Correlation and anomaly rules

Planned deterministic checks:
- duplicate or replayed events;
- out-of-order sequence numbers and unexpected gaps;
- delayed or expired events;
- conflicting state claims from synthetic sources;
- malformed or oversized payloads;
- source or signature validation failures;
- channel loss, recovery, and retry bursts;
- multiple reports that refer to the same simulated incident.

Do not equate multiple reports with independent corroboration: their provenance and correlation may be shared. Statistical or ML anomaly detection may be explored later as an advisory signal, never as the sole decision gate.

### Domain adapters

Adapters translate domain-specific event types into explicit context and policy inputs. The first adapter should be road-disruption simulation: traffic-light outage, collision, road closure, debris/hazard report, stale report, duplicate crowd-sourced report, and contradictory reports.

A road adapter may classify information for an advisory demonstration, but it must not tell a driver to proceed through an intersection or override road signs, traffic lights, emergency services, or official instructions. Railway, aviation, and maritime adapters remain separate follow-on work with synthetic fixtures only.

### Fault-injection controller

Planned controlled faults include latency and jitter, event loss, duplication and replay, reordering, payload corruption, source outage, contradictory state, clock skew, partial service failure, and recovery bursts.

Each scenario defines initial conditions, injected fault, expected detection, expected advisory/review outcome, evidence assertions, and known blind spots.

### Evidence and reporting

Planned local reports will contain scenario configuration, injected events, observed events, validation results, policy outcome, reason codes, timing measurements, and evidence-chain verification result.

The current SHA-256 chain is in-memory and unauthenticated. A future durable evidence design must consider signed checkpoints or independently retained anchors, key custody, crash consistency, and truncation detection. A hash chain alone is not proof of authenticity or tamper-proof storage.

## Initial road-resilience demonstration scenarios

| Scenario | Injected condition | Expected prototype behavior |
|---|---|---|
| Healthy event | Valid, fresh, well-formed road-hazard report | Validate and classify for advisory review |
| Traffic-light outage | Synthetic infrastructure outage event | Surface outage and uncertainty; never infer right-of-way |
| Stale report | Report exceeds configured validity window | Mark stale; do not present as current |
| Duplicate crowd report | Same event submitted repeatedly | Deduplicate or correlate; do not inflate corroboration |
| Contradictory reports | Sources report incompatible road states | Mark context inconsistent and request review |
| Unknown source | Source absent from simulation trust configuration | Mark untrusted or unknown; do not infer identity |
| Corrupted payload | Payload differs from trusted fixture digest | Reject integrity check |
| Clock skew | Source time outside configured uncertainty bounds | Mark freshness indeterminate |
| Connectivity outage | Event stream stops arriving | Report loss of observability within declared assumptions |
| Recovery burst | Reconnection produces duplicate and delayed reports | Preserve replay/order checks and report backlog behavior |

A passing scenario means only that the implementation behaved as specified for that scenario. It does not establish coverage of all failures or attacks.

## Measurement and acceptance criteria

Report measurable results rather than claiming zero risk:
- detection rate for explicitly enumerated injected cases;
- false-positive and false-negative counts for the defined test corpus;
- duplicate suppression and correlation accuracy for labelled fixtures;
- event validation and decision latency under documented local test conditions;
- behavior during outage, recovery, and burst traffic;
- reproducibility from a fixed scenario seed and configuration;
- evidence verification success and known truncation/rewrite limitations;
- test coverage of fail-closed behavior and unexpected exceptions.

Every metric must state its test corpus, environment, assumptions, and limitations. A 100% detection result on a finite synthetic suite must never be generalized into 100% real-world protection.

## Delivery plan

### Phase 1 — Contracts and threat model
- [x] Define a versioned synthetic event envelope.
- [x] Define caller-supplied source allow-list, integrity, freshness, sequence, replay, and clock-skew behavior for the initial validator.
- [ ] Define durable source identity, trust lifecycle, correlation, and trusted clock assumptions.
- [ ] Map remaining threats to explicit invariants and test cases.
- [x] Document behavior for stale, expired, replayed, invalid, and indeterminate inputs.

### Phase 2 — Deterministic event validator
- [x] Implement structural, digest, sequence, replay, and freshness checks.
- [x] Return stable reason codes and structured validation evidence.
- [x] Add tests for malformed, duplicated, non-advancing, stale, expired, future-dated, and digest-mismatched events.
- [ ] Add broader property-based tests and fuzzing for event inputs.

### Phase 3 — Road-disruption simulator
- [ ] Add deterministic synthetic event producers and fixtures.
- [ ] Model traffic-light outage, collision, road closure, hazard reports, duplicate reports, and contradictory information.
- [ ] Add latency, loss, duplication, reordering, corruption, outage, and clock-skew injectors.
- [ ] Make scenarios reproducible and safe to run offline.
- [ ] Add regression fixtures for each documented failure.

### Phase 4 — Domain adapters
- [ ] Reuse the core contracts for a railway-inspired resilience adapter.
- [ ] Evaluate separate maritime and aviation adapters only after domain-specific threat models and scope reviews.
- [ ] Keep every adapter synthetic and non-actuating.

### Phase 5 — Evidence and inspection
- [ ] Produce scenario reports and local inspection views.
- [ ] Measure detection latency and false-positive/negative counts.
- [ ] Evaluate durable evidence, signed checkpoints, and key lifecycle separately.

### Phase 6 — Independent review
- [ ] Conduct an independent architecture and threat-model review.
- [ ] Seek qualified domain review before making domain-specific assurance claims.
- [ ] Keep operational integration out of this portfolio prototype.

## Safety and assurance statement

Kernveil Resilience Lab is a local, synthetic-data research and portfolio prototype. It is not a safety instrumented system, certified transportation product, safety case, navigation service, or production security gateway. It cannot eliminate all communication or technology failures. Its purpose is to make selected failure modes observable, testable, explainable, and reproducible, and to demonstrate bounded handling of uncertainty within explicitly defined simulations.
