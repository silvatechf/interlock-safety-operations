# Risk-to-test and architecture traceability

This matrix links selected risks to the implementation evidence available in this repository. A test demonstrates only the behavior it exercises; it is not proof of system-wide safety.

| Risk ID | Risk / failure mode | Current mitigation | Test evidence | Architecture / boundary reference | Residual limitation |
|---|---|---|---|---|---|
| R-01 | Missing or unauthorized actor is accepted | Deny by default and actor allow-list checks | `tests/test_engine.py::test_missing_actor_denies_by_default`; `tests/test_engine.py::test_unauthorized_actor_is_denied`; `tests/test_properties.py::test_any_missing_or_unlisted_actor_is_denied` | [Architecture — trust boundaries](architecture.md#trust-boundaries) | An actor ID is an assertion, not authenticated identity. |
| R-02 | Unknown command is permitted | Explicit command allow-list | `tests/test_engine.py::test_unknown_command_is_denied` | [Safety boundary](safety-boundary.md#prohibited-interpretation) | No live command execution exists; no operational integration is assessed. |
| R-03 | Required fact is absent or a condition fails | Required-fact checks and explicit conditions | `tests/test_engine.py::test_missing_context_fact_denies`; `tests/test_engine.py::test_failed_condition_denies_and_explains_fact` | [Decision pipeline](architecture.md#decision-pipeline) | Facts are supplied assertions and may be fabricated or contradictory. |
| R-04 | Context is stale or future-dated | Age limit and future timestamp rejection | `tests/test_engine.py::test_stale_context_denies`; `tests/test_engine.py::test_future_context_timestamp_denies`; `tests/test_properties.py::test_any_context_older_than_policy_limit_is_denied` | [Threat model — current mitigations](threat-model.md#current-mitigations) | Clock trust, drift and provenance are not solved by timestamp validation. |
| R-05 | A command ID is replayed within one session | Lock-protected, process-local seen-ID set; duplicates denied and recorded | `tests/test_session.py::test_first_command_is_evaluated_and_duplicate_is_denied`; `tests/test_session.py::test_denied_command_id_is_also_marked_seen`; `tests/test_properties.py::test_session_transition_first_evaluates_then_denies_replays` | [Duplicate handling](architecture.md#duplicate-handling) | State is lost on restart and is not shared across processes or hosts. |
| R-06 | Decision status conflicts with reason codes | Evaluator invariant: reasons imply DENY; no reasons imply ALLOW | `tests/test_properties.py::test_decision_status_matches_presence_of_reasons` | [Decision pipeline](architecture.md#decision-pipeline) | Property generation covers the declared test strategies, not every possible execution. |
| R-07 | Evidence serialization changes silently or malformed data is accepted | Explicit schema version, deterministic serialization, validation on deserialization | `tests/test_serialization.py::test_round_trip_preserves_decision`; `tests/test_serialization.py::test_serialization_is_deterministic`; `tests/test_serialization.py::test_schema_version_is_explicit`; `tests/test_serialization.py::test_unknown_schema_version_is_rejected`; `tests/test_serialization.py::test_malformed_payload_is_rejected` | [Evidence](architecture.md#decision-pipeline) | Serialization is not cryptographic integrity, durable storage, or tamper evidence. |
| R-08 | Demo evaluator is mistaken for an actuator or safety controller | No actuation interface; explicit non-goals and warnings | `tests/test_engine.py::test_evaluation_never_executes_commands` | [Safety boundary](safety-boundary.md#prohibited-interpretation); [README](../README.md#safety-boundary) | A unit test and documentation cannot prevent a downstream integrator from misusing the code. |
| R-09 | Invalid policy structure is accepted | Pydantic model validation rejects malformed conditions and blank entries | `tests/test_engine.py::test_malformed_policy_condition_is_rejected_at_construction`; `tests/test_engine.py::test_blank_policy_members_are_rejected` | [Decision pipeline](architecture.md#decision-pipeline) | Policy authoring authorization, review, signing and rollback are not implemented. |
| R-10 | CI action reference is moved or changes unexpectedly | GitHub Actions pinned to reviewed full commit SHAs; secret scanning runs on PRs | Pull request checks and commit-specific CI results; see [CI security maintenance](ci-security-maintenance.md) | [CI security maintenance](ci-security-maintenance.md#github-actions-pinning) | Pinning and secret scanning reduce specific risks; they do not prove dependencies or workflow logic safe. |

## Highest-priority gaps for this portfolio MVP

1. **Fault injection and broader properties:** exercise exceptions and failure boundaries around evaluation and ledger recording, using synthetic inputs only.
2. **Durability and concurrency:** current replay protection and evidence ledger are process-local; no persistence or cross-process guarantees are claimed.
3. **Trust and governance:** real authentication, trusted fact provenance, trustworthy time, and policy change controls are not implemented.
4. **Independent review:** check that the README, safety boundary, demos and roadmap do not overstate what the implementation proves.

## How to interpret this matrix

- “Test evidence” means a named automated test currently exists; it does not mean the risk is eliminated.
- “Current mitigation” describes implemented code or workflow controls, not a complete security guarantee.
- “Residual limitation” remains part of the public project description and must not be removed merely because tests pass.
- The project remains a local portfolio demonstration using synthetic data, not a certified or operational safety component.
