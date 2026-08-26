# Gate 22 — Spread/copy state provenance

Status: **10/10 state-model checks pass.**

This gate extends the receiver+slot state model from Gates 20–21 to JavaScript/TypeScript copy semantics:

- object spread: `{ ...a }`
- ordered object overrides: `{ ...a, fixed: v }` and `{ fixed: v, ...a }`
- multiple spreads: `{ ...a, ...b }`
- array spread: `[ ...a ]`
- index shifting: `[ prefix, ...a ]`

## Core rule

Spread is modeled as a **snapshot copy of state at that program point**. Order matters. Later explicit properties/spreads overwrite earlier copied slots.

Examples verified:

- source in `a.fixed`; `{...a}` -> copied `fixed` remains source-derived.
- `{...a, fixed: "CONST"}` -> later constant kills the copied source for `fixed`.
- `{fixed: "CONST", ...a}` -> later spread restores `a.fixed` as the reaching value.
- `{...a, ...b}` -> `b.fixed` wins over `a.fixed`.
- `["CONST", ...a]` -> an exact source at `a[0]` moves to result index 1.

## Uncertainty discipline

A dynamic write such as `a[key] = source` before `{...a}` does not become an exact write to every property. The copied object carries an AMBIGUOUS dynamic-slot effect. A later read of `copy["fixed"]` therefore remains AMBIGUOUS with `source` only as a possible origin.

## False-flow control

Copying `a` does not import state from a distinct receiver `b`, even when both have the same property name.

## Verification boundary

The state/copy model is executed and passes 10/10. The existing Gate-21 CSV adapter can parse the fixture and emit CSV, but it does **not yet semantically lower object/array spread into a form the legacy engine understands**. Therefore this is not claimed as a real-engine provenance pass. The next integration gate should emit explicit frontend copy/state summaries (or a neutral copy IR) rather than pretending spread is an ordinary PHP AST construct.
