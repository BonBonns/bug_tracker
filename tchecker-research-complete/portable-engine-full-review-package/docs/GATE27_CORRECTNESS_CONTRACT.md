# Gate 27 — Portable Core Correctness Contract

Gate 27 imports measured lessons from the legacy PHP engine into the language-neutral provenance core before the portable engine grows further.

## Implemented

1. **Semantic local flow**
   - Added language-neutral `LocalFact` and `AssignmentFact`.
   - Added `ValueRef.LOCAL`.
   - Local provenance is evaluated from semantic value relations, not source-language AST subtree membership.
   - Without a reaching-definition proof, a local with zero or multiple definitions abstains as `UNKNOWN` rather than selecting a definition.

2. **Explicit analysis completeness**
   - `COMPLETE`: analysis finished for the represented facts.
   - `UNKNOWN`: an unresolved semantic relation prevents a complete claim.
   - `PARTIAL`: analysis was explicitly truncated by a resource budget.

3. **Visible truncation**
   - Added `AnalysisBudget` with a global work-item budget and a high emergency depth guard.
   - A hit emits a structured `TruncationEvent` (`WORK_BUDGET` or `DEPTH_BUDGET`).
   - Truncation can never silently appear as a complete empty/no-flow result.
   - Default depth is 256, so the legacy hard depth-9 behavior is not copied.

4. **Return relevance by construction**
   - Function summaries depend only on values that reach the return expression.
   - Merely having an input/source elsewhere in a callee does not make the return depend on it.

## Verification

`tests/gates/gate27/run_gate27.sh` executes 12 assertions:

- local assignment + alias chain
- call return flowing through a local
- return-relevance control
- competing local definitions abstain
- missing local definition remains unknown
- exact 21-function chain succeeds (> legacy depth 9)
- explicit depth truncation is PARTIAL and visible
- truncation cannot become NO_FLOW
- explicit work-budget truncation is PARTIAL and visible
- UNKNOWN cannot collapse to a complete empty result
- default budget does not truncate the deep chain
- portable core has no language AST/Joern field dependency

Observed result:

```
GATE27=12/12
ANALYSIS_STATUS=COMPLETE
```

Cumulative result after Gate 27:

```
EXECUTED 17/17
HISTORICAL_RECORDED 8/8
REGRESSIONS 0
GATE 24 BLOCKED
GATE 24-TS BLOCKED
```

The real-Joern gates remain blocked only because `joern`/`jssrc2cpg` are not installed in this runtime.

## Deliberate non-goals

Gate 27 does not yet implement CFG reaching definitions, state/heap persistence, sanitizers, sinks, WordPress behavior, or security semantics. Multiple local definitions therefore abstain until a frontend/core reaching-definition fact is available.
