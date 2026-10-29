# Simulation scenarios

All facts in these examples are synthetic input supplied to a local evaluator. They do not come from sensors, identity providers, service managers, dispatch systems, or other trusted sources. The adapters return decisions only; they do not perform movement or restart services.

## Railway-inspired movement request

An illustrative request is allowed only when the actor matches the simulation allow-list, the context is fresh, and all three facts are explicitly true:

- `route_clear`
- `section_unoccupied`
- `movement_authority_valid`

These booleans do not represent validated railway detection, route locking, movement authority, or any certified signalling function. The example intentionally makes no claims about braking, separation distances, or physical safety.

## IT service restart

An illustrative restart request is allowed only when the actor matches the simulation allow-list, the context is fresh, and all three facts are explicitly true:

- `maintenance_window_open`
- `change_approved`
- `backup_verified`

The adapter does not call a process manager, cloud API, SSH client, or deployment system.

## Run the tests

```powershell
python -m pip install -e ".[dev]"
pytest -q
```

The property tests exercise denied outcomes for missing/unlisted actors and stale contexts across generated inputs. Passing tests do not establish security or safety outside these narrow software properties.
