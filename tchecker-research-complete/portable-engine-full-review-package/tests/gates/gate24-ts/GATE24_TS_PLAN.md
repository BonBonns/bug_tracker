# Gate 24-TS — Real Joern TypeScript conformance

## Purpose
Measure what **real `jssrc2cpg`** gives the portable engine for TypeScript types and dispatch. This gate does not emulate PHP AST nodes and does not add security semantics.

## Fixtures
1. `exact(obj: A)` — directly typed receiver.
2. `unionCall(obj: A | B)` — union receiver; characterize whether Joern resolves 0/1/N targets.
3. `propertyCall(h: Holder)` — typed property `Holder.worker: A`.
4. `returnReceiver()` — typed function return used as receiver.
5. `interfaceCall(w: Worker)` — interface dispatch.
6. `baseCall` / `childCall` — inheritance and override behavior.
7. `genericCall<T extends Worker>` — bounded generic receiver.
8. `anyCall(obj: any)` — intentionally weak type.

## What is a hard pass criterion?
The gate requires Joern to preserve the basic CPG facts the neutral layer needs: methods, formal parameters, nonempty TypeScript types on directly typed parameters, calls, `methodFullName`, typed members, and inheritance metadata.

## What is deliberately *not* preregistered as a pass/fail expectation?
The exact resolution class for union/interface/generic/dynamic cases. Those are empirical questions. The runner records the demonstrated Joern callee set and projects it as:
- 0 callee edges: `UNRESOLVED`
- 1 callee edge: `EXACT` (observed single-target projection only)
- >1 callee edges: `AMBIGUOUS`

We do not infer `HEURISTIC` from string/name similarity.

## Why this matters
If Joern already preserves enough TS type information and call targets, the temporary TypeScript→PHP-shaped adapter can be retired. The portable core consumes the neutral facts instead.

## Current package status
**RUN and PASSED against a real Joern install** (joern-cli, `codepropertygraph-domain-classes 1.7.70`, installed from the official `joernio/joern` GitHub release). Verified 2026-08-20 with `JSSRC2CPG`/`JOERN` pointed at the real executables:

```text
GATE24_TS=27/27
```

### Real-frontend schema fix required

The first real run failed at export time, not at the check stage:

```text
value closureOriginalName is not a member of io.shiftleft.codepropertygraph.generated.nodes.ClosureBinding
```

`export_ts_facts.sc` referenced `ClosureBinding.closureOriginalName`, which does not
exist on this Joern version's `ClosureBinding` node (only `closureBindingId` and
`evaluationStrategy` remain there now). Confirmed by decompiling the shipped
`ClosureBindingBase.class`. Checked `capture_facts.py`, the only downstream consumer
of `closure_bindings.tsv`: it reads column 1 (`closureBindingId`) and column 3
(`refs`) and never reads the original-name column, so the field was replaced with an
empty placeholder to preserve the TSV column layout, with no semantic change to
capture facts. See the inline comment at that line in `export_ts_facts.sc`.

This is exactly the kind of real-frontend drift `CURRENT_CONCERNS_AND_OPEN_WORK.md`
flagged as unvalidated — the fixture/dispatch-projection logic itself needed no
changes; only this schema mismatch did.

As with Gate 24, this package previously shipped a `run/` directory already
claiming `GATE24_TS=27/27` while `local_attempt.err` recorded
`REAL_JOERN_TS_BLOCKED: jssrc2cpg not found`. That artifact could not have been
produced against this Joern version without hitting the `closureOriginalName`
error above, so it should not have been trusted. The regenerated run (after the
fix) reproduces the same 27/27 result and observation values as the stale
artifact, so the projection logic itself was sound — only the export script's
compatibility with this Joern version was stale.
