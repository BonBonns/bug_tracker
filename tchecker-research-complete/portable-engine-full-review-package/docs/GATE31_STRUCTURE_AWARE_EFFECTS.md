# Gate 31 — structure-aware transformation chains

Gate 31 moves the transformation-effect model from a flat registry lookup to a structured semantic path.
The core represents source values, transformation applications, alternative control-flow branches, and explicit
parser/use-context boundaries without referring to any source-language AST node kind.

## Core invariant

A transformation can satisfy only a context boundary that occurs *after* it along the source-to-sink path.
Crossing a boundary closes that segment. A later transformation cannot retroactively satisfy an earlier parser layer.
This prevents the flattened-subtree bug class where merely finding a transformation somewhere under a sink is treated
as proof that it encloses the relevant value in the right context.

## Nested contexts

Nested interpretation is represented as ordered context boundaries. For example:

```
source
  -> encodeInner
  -> CONTEXT syntax/inner-parser
  -> encodeOuter
  -> CONTEXT presentation/outer-render
```

Both layers are mandatory. One correct transformation cannot be reused to satisfy multiple parser layers unless the
profile explicitly registers adequacy for each layer and the operation occurs in the corresponding structural segment.

## Branches and abstention

Branches are evaluated separately. All-guaranteed branches produce GUARANTEED; a transformed branch plus a raw
pass-through branch is CONDITIONAL; an unmodelled transformation remains UNKNOWN. No branch is silently discarded.

The evaluator retains the ordered structural steps and per-context layer assessments as evidence.
