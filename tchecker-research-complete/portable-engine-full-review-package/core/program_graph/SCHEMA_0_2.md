# portable-program-facts/0.2

Required top-level fields:
- `schema`: exactly `portable-program-facts/0.2`
- `frontend`: frontend identifier
- `metadata`: object or list of objects
- `type_decls`, `members`, `functions`, `method_returns`, `locals`, `calls`, `identifiers`, `returns`

## Function
`id`, `name`, `full_name`, `signature`, `file`, `line`, `line_end`, `is_external`, `parameters[]`

## Parameter
`id`, `method_id`, `index`, `name`, `code`, `type_full_name`, `line`

## Type declaration
`id`, `name`, `full_name`, `file`, `line`, `is_external`, `inherits_from[]`

## Member
`id`, `type_decl_id`, `name`, `code`, `type_full_name`, `line`

## Method return
`id`, `method_id`, `code`, `type_full_name`, `line`

## Local
`id`, `method_id`, `name`, `code`, `type_full_name`, `line`

## Call
`id`, `enclosing_function_id`, `name`, `method_full_name`, `dispatch_type`, `type_full_name`, `code`, `file`, `line`, `candidate_target_ids[]`, `candidate_target_full_names[]`, `resolution`, `arguments[]`

## Resolution invariants
- `EXACT`: exactly one demonstrated candidate target.
- `AMBIGUOUS`: at least two demonstrated candidate targets.
- `UNRESOLVED`: zero demonstrated candidate targets.
- `HEURISTIC`: one or more candidates supplied by an explicitly heuristic frontend rule; it is never inferred merely from string similarity by the neutral normalizer.

The neutral core must never reinterpret `AMBIGUOUS` or `UNRESOLVED` as an exact edge.

## Gate-26 value relations (optional extension within 0.2)
The `returns` list may carry a language-neutral `value` relation and call arguments may
carry a corresponding `value` relation. The Java API represents these with `ValueRef`:
- `PARAMETER`: references a `ParameterFact.id`
- `CALL`: references a `CallFact.id`
- `CONSTANT`: demonstrated internal/constant value
- `UNKNOWN`: relation not established

These relations are intentionally semantic and contain no PHP AST node kinds. Frontends
that do not yet export them remain valid 0.2 producers; consumers must treat missing
relations as UNKNOWN rather than infer them.
