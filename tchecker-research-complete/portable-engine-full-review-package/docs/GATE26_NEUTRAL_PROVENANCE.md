# Gate 26 — First neutral provenance consumer

## Purpose
Extract the first executable provenance logic that consumes only `ProgramGraph` facts,
independent of `PHPCGFactory`, PHP AST classes, WordPress, sources/sinks, or sanitizers.

## Scope
Gate 26 handles only:
- function parameters,
- call arguments,
- demonstrated call targets,
- return expressions,
- interprocedural argument → parameter → return projection,
- resolution strength (`EXACT`, `HEURISTIC`, `AMBIGUOUS`, `UNRESOLVED`).

It deliberately does **not** model heap/state, closures, framework callbacks, security
sources/sinks, or sanitizer semantics yet.

## New neutral primitives
- `ValueRef`: PARAMETER | CALL | CONSTANT | UNKNOWN.
- `ReturnFact`: a function return expression represented by a `ValueRef`.
- `PortableProvenanceEngine`: computes return provenance in terms of the enclosing
  function's parameter indexes.
- `ProvenanceSummary`:
  - `provenPositions`: contributions demonstrated on every alternative,
  - `mayPositions`: contributions possible on some alternatives or through heuristic evidence,
  - `unknown`: unresolved relation remains,
  - `resolution`: weakest demonstrated resolution on the path.

## Safety rules verified
- EXACT call + exact callee return may become proven provenance.
- AMBIGUOUS divergent targets produce MAY, not a fabricated hard dependency.
- If every ambiguous target depends on the same argument, the dependency is common/proven,
  but path resolution remains AMBIGUOUS.
- HEURISTIC targets never harden provenance; their dependencies are MAY only.
- UNRESOLVED calls remain UNKNOWN.
- An exact wrapper cannot wash away an AMBIGUOUS callee path.
- A callee that ignores an argument does not create caller provenance from that argument.

## Verification
`tests/gates/gate26/run_gate26.sh` executes 10 tests:

1. direct parameter return
2. constant return
3. argument → parameter → return
4. two-hop argument-position remapping
5. callee drops argument
6. ambiguous divergent targets
7. ambiguous targets with shared dependency
8. unresolved call stays UNKNOWN
9. heuristic call never hardens
10. weakest resolution survives an exact wrapper

Result:

```
GATE26=10/10
```

Cumulative runnable regression:

```
EXECUTED 16/16
REGRESSIONS 0
```

The canonical legacy detector also rebuilds and Gate 23 remains `25/25`, showing the
neutral-core addition did not regress the existing canonical engine.

## Architectural result
There is now an executable path that does not pass through PHP-shaped AST classes:

```
ProgramGraph
    ↓
PortableProvenanceEngine
    ↓
ProvenanceSummary
```

This is the first actual extraction of provenance behavior out of the legacy PHP factory,
not merely a directory reorganization.

## Next task
Make a real frontend adapter populate Gate-26 `ValueRef`/`ReturnFact` relations from
actual Joern CPG facts. Gate 24/24-TS remain blocked in this runtime because Joern is not
installed, so the next local extraction can alternatively move local assignment/value-flow
facts into `ProgramGraph` while preserving the same fail-closed semantics.
