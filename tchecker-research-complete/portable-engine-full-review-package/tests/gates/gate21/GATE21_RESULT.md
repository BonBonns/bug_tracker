# Gate 21 — Destructuring provenance

Status: **11/11 frontend/model checks pass.**

This gate extends Gate 20 indexed/container provenance into JavaScript/TypeScript destructuring.

## Exact lowerings

The adapter lowers exact destructuring bindings into the already-supported `AST_DIM` form rather than teaching the legacy core JavaScript-specific destructuring syntax.

Examples:

- `const { fixed } = box` -> `fixed = box["fixed"]`
- `const { fixed: renamed } = box` -> `renamed = box["fixed"]`
- `const [first] = arr` -> `first = arr[0]`
- `const [, second] = arr` -> `second = arr[1]`

This preserves the receiver+key/index identity established in Gate 20.

## Results

- object exact destructure -> EXACT source parameter
- object rename -> EXACT source parameter
- different property -> no source flow
- constant overwrite -> source killed
- array index 0 -> EXACT source parameter
- array index 1 control -> no source flow
- computed property destructure (`{[key]: picked}`) -> AMBIGUOUS, source remains possible
- object rest -> AMBIGUOUS
- array rest -> AMBIGUOUS
- distinct receiver, same property name -> no cross-object source flow
- generated CSV contains lowered `AST_DIM` nodes

## Important uncertainty rule

Computed destructuring and rest are not flattened into hard/exact provenance. A dynamic key may refer to multiple slots, and a rest binding represents multiple residual slots, so this gate leaves them AMBIGUOUS rather than converting the whole container into an exact source.

## Verification boundary

The TypeScript frontend/model and CSV generation are executed and verified in this runtime. The full compiled detector tree used for the prior real-engine gates is not present in this runtime, so Gate 21 is **not claimed as a real-engine pass yet**. The generated `nodes.csv`/`rels.csv` and adapter are packaged for that follow-up run.

Pass result: `GATE21=11/11`.
