# Gate 16 — uncertain provenance through expressions

## First: Gate 15 is now real-engine verified
The full Gate-14 detector tree was present in the runtime after all. Gate 15 was copied into that tree, rebuilt successfully, and executed on the generated Gate-15 CSV with both state sidecars enabled.

Measured Gate-15 results:
- `wrapMayLocal` -> MAY `AMBIGUOUS [1]`
- `wrapMayLocal2` -> MAY `AMBIGUOUS [1]`
- `wrapUnknownLocal` -> MAY `UNKNOWN []`
- `localUnrelated` -> no MAY summary
- `localOverwrite` -> no MAY summary

All of those functions remained empty on the hard return-taint channel. So Gate 15 is no longer shape-only; it is real-engine run verified.

## Gate 16 goal
Carry MAY/UNKNOWN provenance through ordinary expression composition without promoting it to hard provenance.

New cases:

```ts
const y = mayAliasWrite(cond, source);
return identity(y);
```

```ts
const y = mayAliasWrite(cond, source);
return cond ? y : "CONST";
```

and negative controls where a wrapper returns a constant or where a conditional contains only ordinary exact parameter provenance.

## Engine change
Gate 16 replaces the narrow "resolve return to one call" helper with a conservative expression-level MAY tracer.

It handles:
- unique local aliases;
- calls whose callee already has a MAY/UNKNOWN return summary;
- exact/hard return wrappers: MAY survives only through callee argument positions already proven to reach the return;
- conditional expressions: arm results are unioned, and one-arm-only MAY is capped at `AMBIGUOUS`.

A plain caller parameter is not itself treated as MAY. Uncertainty must originate from the MAY channel.

The hard `returnTaintPositions` channel remains untouched.

## Adapter change
The TypeScript CSV adapter now emits `AST_CONDITIONAL` with the legacy three-child shape:
- child 0 = condition
- child 1 = true expression
- child 2 = false expression

## Real-engine results
The full detector rebuilt successfully and executed the Gate-16 fixture.

Key output:

- `identity(x)` -> hard `[0]`
- `constantize(x)` -> hard `[]`
- `wrapMayThroughIdentity` -> MAY `AMBIGUOUS [1]`, hard `[]`
- `wrapMayThroughIdentity2` -> MAY `AMBIGUOUS [1]`, hard `[]`
- `wrapUnknownThroughIdentity` -> MAY `UNKNOWN []`, hard `[]`
- `wrapMayThroughConstantize` -> no MAY, hard `[]`
- `wrapMayConditional` -> MAY `AMBIGUOUS [1]`, hard `[]`
- `conditionalExactOnly` -> hard `[1]`, no MAY

The existing Gate-15 local-assignment cases also remained correct.

`gate16_test.py`: **13/13 PASS**.

Runtime instrumentation:

`FRONTEND_STATE_RETURN loaded=1 rejected=0 complete=1`

`FRONTEND_STATE_MAY loaded=4 rejected=0 uncertain=4`

`RETURN_MAY_SUMMARY functions=14 rounds=2`

## What this establishes
The portable uncertain-provenance channel now survives:

```text
uncertain heap/state
  -> function return
  -> local assignment / alias
  -> exact identity-style call
  -> conditional expression
  -> caller return summary
```

without laundering uncertainty into exact taint.

The next meaningful gap is expression composition with **multiple uncertain operands / non-call operators** (binary/template/string composition) and then a downstream evidence consumer that can display MAY provenance without treating it as a hard source path.
