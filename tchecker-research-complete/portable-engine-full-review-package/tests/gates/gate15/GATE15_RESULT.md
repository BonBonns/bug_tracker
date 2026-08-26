# Gate 15 — MAY provenance through local assignment/return chains

## Goal
Extend Gate 14's uncertain return-provenance fixed point from direct wrappers:

```ts
return mayAliasWrite(cond, source);
```

to ordinary local assignment chains:

```ts
const y = mayAliasWrite(cond, source);
return y;
```

and:

```ts
const y = wrapMayLocal(cond, source);
const z = y;
return z;
```

without laundering AMBIGUOUS/UNKNOWN provenance into the hard `returnTaintPositions` channel.

## Engine change
`PHPCGFactory_gate15.java` adds `resolveMayReturnCall(Expression, fid, depth)`.

It accepts only:
- a direct call expression; or
- a local variable with exactly one defining assignment in the same function, recursively up to depth 8.

It deliberately abstains when a returned variable has multiple definitions. This is important for overwrite/branch cases: Gate 15 does not guess a reaching definition.

`buildReturnMayTaintSummaries()` now calls this helper before mapping callee MAY positions to caller parameters. The existing MAY/hard-channel separation is unchanged.

## New fixtures
- `wrapMayLocal` — one local assignment, expected MAY `AMBIGUOUS [1]`.
- `wrapMayLocal2` — two local aliases plus an interprocedural MAY hop, expected MAY `AMBIGUOUS [1]`.
- `wrapUnknownLocal` — local assignment carrying `UNKNOWN []`.
- `localUnrelated` — MAY-producing call assigned to `y`, but returns unrelated constant `z`; expected no MAY summary.
- `localOverwrite` — MAY-producing assignment followed by a second definition of the returned local; expected abstention/no MAY summary.

## Verification performed in this runtime
The TypeScript adapter successfully emitted Gate-15 CSV input: 559 node rows and 558 relation rows.

A structural mirror of the new Java helper was run over those generated CSVs and passed 5/5:

```text
PASS wrapMayLocal -> mayAliasWrite
PASS wrapMayLocal2 -> wrapMayLocal
PASS wrapUnknownLocal -> mayAliasDifferentField
PASS localUnrelated -> None
PASS localOverwrite -> None
GATE15_SHAPE=5/5
```

This verifies that the generated AST shape supports the exact local-definition discipline implemented in the Java patch, including both abstention controls.

## Verification boundary
This runtime does not contain the full detector source tree/classes that were present when Gate 14 was built and run. Therefore Gate 15 has **not** been recompiled into the complete detector or executed through the real `PHPCGFactory` here.

Do not label Gate 15 run-verified yet. The remaining promotion check is:
1. replace Gate-14 factory with `PHPCGFactory_gate15.java` in the full engine tree;
2. rebuild;
3. run Gate 15 with the same hard + uncertain sidecars;
4. require the three local wrappers to receive the expected MAY summaries;
5. require `localUnrelated` and `localOverwrite` to remain absent from MAY;
6. verify all MAY wrappers remain absent from hard `returnTaintPositions`;
7. rerun Gate 14 as regression.

## Expected architectural result
If the real-engine run passes, MAY provenance will survive:

```text
uncertain heap/state result
  -> function return
  -> local assignment
  -> local alias
  -> return
  -> caller
```

without converting uncertainty into exact taint.
