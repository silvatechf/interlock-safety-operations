# Sentinel Interlock

**Policy enforcement for safety-critical operations.**

An experimental, local-first reference implementation for evaluating whether an operational command should be permitted under explicit policy, authorization, state, freshness, and evidence constraints.

The MVP combines a generic policy-enforcement core with domain-specific simulation adapters. Initial examples are a railway-inspired simulator and generic IT operations.

> **Safety boundary:** This is a research and portfolio MVP, not a railway interlocking, train protection system, industrial safety controller, or certified safety component. Never connect it to operational signalling, braking, dispatch, PLCs, production systems, or other safety-critical infrastructure. A demo decision is not a real-world safety guarantee.

## Goals

- Explainable, deterministic allow-or-deny decisions.
- Fail closed when required data is missing, stale, inconsistent, or unauthorized.
- Keep generic policy logic separate from domain-specific constraints.
- Provide structured decision evidence.
- Test failure modes and invariants, not only happy paths.
- Remain local-first and easy to run.

## Non-goals

- Replacing certified safety systems or human operational procedures.
- Calculating real braking curves, railway separation distances, route locking, or track occupancy.
- Claiming compliance or certification.
- Connecting to live telemetry or operational control paths.

## Architecture

```text
Simulation adapter -> policy enforcement core -> decision + evidence
                              |
                  no command execution/actuation
```

The generic core must not define railway distances, braking limits, occupancy interpretations, or industrial thresholds. Domain constraints belong in explicitly scoped simulation adapters.

## Quick start

Python 3.12 is the development baseline.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy src
```

## Status

Early foundation. Tests demonstrate only the software properties they cover, not operational safety or suitability.

## Docs

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Safety boundary and hazards](docs/safety-boundary.md)
- [Roadmap](docs/roadmap.md)
- [Documentación en español](docs/es/README.md)

## License

MIT — see [LICENSE](LICENSE).
