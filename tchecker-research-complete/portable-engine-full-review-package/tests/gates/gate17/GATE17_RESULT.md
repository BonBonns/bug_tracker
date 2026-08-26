# Gate 17 — multi-value / non-call expression MAY provenance

## Goal
Extend the Gate-16 uncertain-provenance tracer through ordinary non-call expression composition without hardening MAY/UNKNOWN facts into `returnTaintPositions`.

This gate specifically covers binary/string composition and TypeScript template literals.

## Engine change
`traceMayExpr()` now handles `BinaryExpression` by tracing both operands and unioning their MAY positions. Resolution is the weakest resolution carried by either uncertain operand.

A binary expression differs from a conditional: if only one operand carries MAY, the result definitely consumes that operand, so the gate does not add a new `AMBIGUOUS` cap merely because the other operand is constant.

The hard return-taint channel is unchanged.

## Adapter change
The TS adapter now emits:

- ordinary binary expressions as `AST_BINARY_OP` with PHP-compatible flags such as `BINARY_ADD`, `BINARY_SUB`, and `BINARY_IS_IDENTICAL`;
- template literals as nested `AST_BINARY_OP` nodes with `BINARY_CONCAT`.

No JavaScript-specific expression class was added to the legacy engine.

## Real-engine results
The full detector rebuilt successfully and executed the Gate-17 CSV with the existing exact and uncertain state sidecars.

Measured results:

- `wrapMayConcat` -> MAY `AMBIGUOUS [1]`, hard `[]`
- `wrapMayConcatTwo` -> MAY `AMBIGUOUS [1,3]`, hard `[]`
- `wrapUnknownConcat` -> MAY `UNKNOWN []`, hard `[]`
- `wrapMayTemplate` -> MAY `AMBIGUOUS [1]`, hard `[]`
- `wrapMayTemplateTwo` -> MAY `AMBIGUOUS [1,3]`, hard `[]`
- `concatExactOnly` -> hard `[0,1]`, no MAY summary
- `binaryUnrelated` -> hard `[]`, no MAY summary

Gate-16 controls remain correct.

`gate17_test.py`: **14/14 PASS**.

Runtime instrumentation:

- `FRONTEND_STATE_RETURN loaded=1 rejected=0 complete=1`
- `FRONTEND_STATE_MAY loaded=4 rejected=0 uncertain=4`
- `RETURN_MAY_SUMMARY functions=19 rounds=2`

## What this establishes
Uncertain provenance can now survive and compose through multiple operands:

```text
MAY source A --\
               + / template composition -> MAY {A,B}
MAY source B --/
```

while exact-only binary provenance stays on the existing hard channel and unrelated MAY-producing calls do not contaminate a returned constant expression.

## Important observation
The legacy sanitizer-classification pass printed `WPINTSAN inferred integer sanitizer` for several new concat-only helper functions. That does not affect this non-security provenance gate, but it is another example of why the language-portability frontend should remain separate from WordPress/security inference passes. No Gate-17 assertion depends on those labels.

## Next boundary
The engine can now *carry* MAY provenance, but normal downstream evidence/reporting still primarily reasons in terms of hard provenance. The next gate should expose MAY/UNKNOWN in a downstream evidence record while guaranteeing that it is not rendered as a hard source path or used to upgrade a vulnerability verdict.
