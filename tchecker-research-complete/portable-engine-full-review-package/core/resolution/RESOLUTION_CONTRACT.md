# Resolution Contract

Every frontend-derived call relationship has a resolution class:

- `EXACT`: one frontend-proven target; may be projected into the legacy hard call graph.
- `HEURISTIC`: plausible but non-proven target; never silently treated as exact.
- `AMBIGUOUS`: multiple possible targets; preserve candidate set and cap path confidence.
- `UNRESOLVED`: target not established.

Path resolution is the weakest resolution encountered. `AMBIGUOUS` and `UNRESOLVED`
must not be projected into hard provenance/source facts.
