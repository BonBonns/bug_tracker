# Portable transformation-effect contract

Gate 30 replaces the architectural idea of a flat `Set<String> sanitizers` with a generic relation:

```text
operation × effect_class × use_context -> adequacy
```

The portable core does **not** contain WordPress escapers, vulnerability classes, or security verdicts.
It only provides the type system needed so a future profile cannot accidentally treat an operation as
universally adequate merely because its name appears in a set.

`Adequacy` is one of `GUARANTEED`, `CONDITIONAL`, `INADEQUATE`, or `UNKNOWN`.
Missing rules abstain as `UNKNOWN`.

`BranchEffectSummary` enforces the all-path rule: a wrapper is `GUARANTEED` only when every alternative
branch is guaranteed for the same effect/context. A partial/pass-through wrapper cannot become globally trusted.

## Gate 31: structure-aware chains

`EffectExpr` and `StructureAwareTransformationEvaluator` preserve enclosure, branch structure, and ordered
`ContextBoundary` layers. Transformation adequacy is evaluated only within the structural segment preceding each
context boundary; later operations cannot retroactively satisfy earlier contexts. This is intentionally semantic IR,
not AST-subtree membership.
