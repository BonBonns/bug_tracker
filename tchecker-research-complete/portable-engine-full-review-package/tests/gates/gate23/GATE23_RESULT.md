# Gate 23 — JavaScript/TypeScript closures and lexical capture

## Result

**PASS: 25/25 checks.**

This gate adds the first explicit JS/TS closure model to the portability prototype and verifies it at three levels:

1. TypeScript semantic model for lexical bindings/captures.
2. Projection into the legacy engine's real `AST_CLOSURE` / `AST_CLOSURE_USES` / `AST_CLOSURE_VAR` CSV vocabulary.
3. Real-engine consumption through exact local-closure call edges plus a gated exact closure-return-summary bridge.

The unmodified legacy engine accepts the generated closure graph and completes analysis. With the Gate-6 exact-call bridge, 10 direct local closure calls are connected to their real `AST_CLOSURE` targets. With the new Gate-23 closure-return bridge, all ten named fixture functions receive the expected exact parameter-dependency summaries.

## Semantics verified

| Fixture | Expected return dependency |
|---|---|
| `closureDirect(source)` | `source` |
| `closureParam(source)` | `source` |
| `closureShadow(source)` | constant only |
| `closureUnrelated(source)` | constant only |
| `closureAlias(source)` | `source` |
| `closureMutation(source)` | constant only |
| `closureMutationToSource(source)` | `source` |
| `nestedClosure(source)` | `source` |
| `closureTwoCaptures(a,b)` | `a`, `b` |
| `closureLocalShadowsOuter(source)` | constant only |

The mutation controls are important: JS closures capture **bindings**, not a value snapshot. Therefore a closure created while `x=source` but invoked after `x="CONST"` returns the constant; reversing the assignment returns `source`.

## Real-engine measurements

The generated CSV contains 11 closure nodes (the nested-closure fixture contains two). The legacy engine accepts the graph and reaches `ANALYSIS_STATUS=COMPLETE`.

Exact local closure-call resolution:

```text
FRONTEND_RESOLUTION loaded=10 exact_edges_added=10 rejected=0 classes={EXACT=10}
```

Exact closure-derived outer-function summaries:

```text
FRONTEND_CLOSURE_RETURN loaded=10 rejected=0 complete=10
```

Examples from the real engine:

```text
RET closureDirect              positions=[0]
RET closureAlias               positions=[0]
RET closureMutation            positions=[]
RET closureMutationToSource    positions=[0]
RET nestedClosure              positions=[0]
RET closureTwoCaptures         positions=[0, 1]
RET closureLocalShadowsOuter   positions=[]
```

With the closure-return bridge disabled, capture-dependent functions such as `closureDirect`, `closureAlias`, `nestedClosure`, and `closureTwoCaptures` lose those dependencies, while the ordinary parameter-only closure case continues to work. This isolates the remaining legacy limitation to lexical environment/capture semantics rather than ordinary closure parsing or parameter propagation.

## Architectural result

The frontend now has an explicit closure boundary:

```text
JS/TS lexical environment
        ↓
AST_CLOSURE + capture manifest
        ↓
EXACT local closure-call resolution
        ↓
frontend closure return summary
        ↓
existing return-provenance fixed point
```

This deliberately does **not** pretend PHP closure semantics and JavaScript closure semantics are identical. `AST_CLOSURE_USES` is used as an input projection, while the frontend semantic model retains JavaScript's reference-to-binding capture behavior.

## Honest boundary

Gate 23 does not yet provide a native heap/environment object inside the legacy DDG. The exact frontend closure-return summary is the bridge. Direct locally-bound closure calls are wired into the call graph; a closure returned from another closure/function is handled by the frontend summary in this gate rather than by a native closure-object call edge (`g()` in `nestedClosure`).

The next natural gate is higher-order functions/callbacks, where closures are passed as arguments and invoked by another function. That will test whether callable identity and capture provenance survive an argument→parameter boundary.
