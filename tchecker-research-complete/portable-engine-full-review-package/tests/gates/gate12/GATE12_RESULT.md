# Gate 12 — alias-sensitive object-state provenance

## Goal
Test whether the Gate-10/11 state abstraction survives ordinary JavaScript/TypeScript reference aliases without either losing same-object flow or merging distinct receivers/fields.

No security source/sink semantics are involved.

## Fixture cases

- `aliasSame(h, source)`: `x = h.worker; y = x; y.setValue(source); return h.worker.readValue()`.
- `aliasAllocation(source)`: two aliases of the same `new A()` allocation.
- `aliasOverwrite(source)`: source write through one alias, constant overwrite through another alias.
- `aliasDistinct(source)`: aliases refer to two distinct `new A()` allocation sites.
- `aliasDifferentField(source)`: same receiver alias, but write `other` and read `value`.
- `aliasDifferentParams(h, other, source)`: aliases originate from two distinct object parameters; no alias is assumed between them.

## Frontend state-model results

- `aliasSame` -> `PARAM:aliasSame.source`
- `aliasAllocation` -> `PARAM:aliasAllocation.source`
- `aliasOverwrite` -> `CONST:"CONST"`
- `aliasDistinct` -> `STATE_UNKNOWN` for the untouched allocation
- `aliasDifferentField` -> `STATE_UNKNOWN` for the untouched field
- `aliasDifferentParams` -> `STATE_UNKNOWN` for `h.worker.value`

Only the first three are COMPLETE, so only those three are allowed into the Gate-11 return-summary bridge.

## Real-engine result

With call-resolution bridge enabled but state-return bridge disabled:

- `aliasSame`: `[0]`
- `aliasAllocation`: `[]`
- `aliasOverwrite`: `[]`
- `aliasDistinct`: `[]`
- `aliasDifferentField`: `[]`
- `aliasDifferentParams`: `[0]`

With both bridges enabled:

- `aliasSame`: `[1]`
- `aliasAllocation`: `[0]`
- `aliasOverwrite`: `[]`
- `aliasDistinct`: `[]`
- `aliasDifferentField`: `[]`
- `aliasDifferentParams`: `[0]`

The engine reported `FRONTEND_RESOLUTION loaded=13 exact_edges_added=13 rejected=0 classes={EXACT=13}` and `FRONTEND_STATE_RETURN loaded=3 rejected=0 complete=3`.

`gate12_test.py`: **7/7 PASS** (six paired expectations plus the explicit no-source-crossflow invariant for distinct object parameters).

## What this establishes

Receiver identity can survive local alias chains: writes through `y` are visible through `x`, the original local, or the original property expression when all denote the same receiver identity. A later constant overwrite through another alias kills the earlier source dependency. Distinct allocation sites and distinct property paths do not merge.

For separate object parameters, the model deliberately does not assume aliasing. Because that case remains `STATE_UNKNOWN`, no COMPLETE state summary is injected; importantly, parameter 2 (`source`) is not manufactured into the real engine's return provenance.

## Boundary

This gate models must-alias relationships created by direct local reference assignments and exact property paths. It does not yet model conditional aliases, collection/array aliases, closure-captured object aliases, prototype mutation, or may-alias joins across branches. Those should remain ambiguous/unknown until explicitly modeled.
