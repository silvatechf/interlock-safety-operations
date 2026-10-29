# Roadmap

## Milestone 0 — Foundation

- [x] Establish scope, non-goals, safety boundary, and threat model.
- [x] Add a small policy evaluator and deterministic tests.
- [x] Verify CI execution and resolve discovered issues.

## Milestone 1 — Core contracts

- [x] Add initial property-based tests for deny-by-default behavior.
- [ ] Validate malformed policy configuration at construction/load time.
- [ ] Define duplicate-command handling without claiming persistence before it exists.
- [ ] Define versioned evidence serialization.

## Milestone 2 — Simulators

- [x] Railway-inspired simulator using synthetic state only.
- [x] IT operations adapter for simulated maintenance/restart commands.
- [x] Document scenario assumptions, adversarial cases, and limitations.
- [x] Keep all scenarios free of physical-world integration and actuation.

## Milestone 3 — Engineering assurance

- [ ] Expand state-transition models and invariants.
- [ ] Add fault injection and broader fuzz/property tests.
- [ ] Add secret scanning and review CI action pinning.
- [ ] Trace risks to tests and architecture decisions.
- [ ] Independent review of claims and scope.

## Release gate

A passing pipeline is a quality signal, not a safety case. Do not describe this project as production-ready, certified, compliant, or suitable for operational control.
