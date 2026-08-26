# Neutral frontend fact contract (Gate 24)

This is the first real-frontend boundary. Language frontends produce facts; the
portable analysis core consumes these facts. No frontend is required to emulate PHP
AST node kinds.

## Function facts
- `id`: frontend-local stable node id for this graph
- `name`, `full_name`, `signature`
- `file`, `line`, `line_end`
- `parameters[]`: `id`, `index`, `name`, `type_full_name`

## Call facts
- `id`, `enclosing_function_id`
- `name`, `method_full_name`, `dispatch_type`, `type_full_name`
- `code`, `file`, `line`
- `arguments[]`: `id`, `index`, `code`, `kind`, `name`, `type_full_name`
- `candidate_target_ids[]`
- `resolution`: `EXACT | HEURISTIC | AMBIGUOUS | UNRESOLVED`

Resolution is deliberately distinct from dispatch type. A dynamic-language call may
be `DYNAMIC_DISPATCH` while still having a single frontend-proven target. Conversely,
a call with no demonstrated target remains `UNRESOLVED`.

## Resolution projection
- one demonstrated callee whose full name agrees with the call's `method_full_name` -> EXACT
- multiple demonstrated callees -> AMBIGUOUS
- no demonstrated callee -> UNRESOLVED
- HEURISTIC is reserved for an explicit frontend heuristic and is never inferred by
  the normalizer merely from name similarity.

This Gate does not define security sources or sinks.
