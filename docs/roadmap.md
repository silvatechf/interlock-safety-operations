# Roadmap

## Milestone 0 — Foundation

- [x] Establish scope, non-goals, safety boundary, and threat model.
- [x] Add a small policy evaluator and deterministic tests.
- [ ] Verify CI execution and resolve discovered issues.

## Milestone 1 — Core contracts

- [ ] Add property-based tests for deny-by-default behavior.
- [ ] Validate malformed policy configuration before evaluation.
- [ ] Define duplicate-command handling without claiming persistence before it exists.
- [ ] Define versioned evidence serialization.

## Milestone 2 — Simulators

- [ ] Railway-inspired simulator using synthetic state only.
- [ ] IT operations adapter for simulated maintenance/restart commands.
- [ ] Document scenario assumptions, adversarial cases, and limitations.
- [ ] No physical-world integration or actuation.

## Milestone 3 — Engineering assurance

- [ ] State-transition model and invariants.
- [ ] Fault injection, fuzzing, and property tests.
- [ ] Dependency and secret scanning in CI.
- [ ] Trace risks to tests and architecture decisions.
- [ ] Independent review of claims and scope.

## Release gate

A passing pipeline is a quality signal, not a safety case. Do not describe this project as production-ready, certified, compliant, or suitable for operational control.
