# Gate 4 — TypeScript receiver-type narrowing

## Goal
Demonstrate that the same syntactic method call can remain ambiguous in JavaScript/untyped code but resolve exactly when a TypeScript receiver annotation identifies the class, while leaving the existing analysis engine unchanged.

## Fixture
Two unrelated classes define the same method:

- `A.process(x) -> x`
- `B.process(x) -> "CONST"`

Four calls are tested:

1. `untyped(obj, input) -> obj.process(input)`
2. `typed(obj: A, input) -> obj.process(input)`
3. `unionTyped(obj: A | B, input) -> obj.process(input)`
4. `missing(obj: A, input) -> obj.missing(input)`

## Frontend resolution result
`resolution_manifest.json` reports:

- untyped receiver -> `AMBIGUOUS`, targets `{A.process, B.process}`
- `obj: A` -> `EXACT`, target `A.process`
- `obj: A | B` -> `AMBIGUOUS`, targets `{A.process, B.process}`
- typed receiver + nonexistent method -> `UNRESOLVED`

This is the intended `EXACT / AMBIGUOUS / UNRESOLVED` contract.

## Adapter change
The adapter now parses `.ts`/`.tsx` with the TypeScript parser and places a simple class type annotation into the existing `AST_PARAM` type slot:

`AST_PARAM child 0 -> AST_NAME("A")`

Complex/union types are deliberately **not** flattened into one class in the legacy CSV. They remain unresolved in the legacy engine while the frontend sidecar preserves the correct `AMBIGUOUS` target set.

## Real-engine result
The existing engine was run without any TypeScript-specific engine patch.

Method-call nodes:

- node 63, line 10: untyped `obj.process` -> **no hard edge**
- node 87, line 15: typed `obj: A; obj.process` -> **edge to node 13 (`A.process`)**
- node 110, line 20: `obj: A | B; obj.process` -> **no hard edge**
- node 134, line 25: `obj: A; obj.missing` -> **no hard edge**

Observed `call2mtd`:

```text
EDGE 87 -> [13]
```

Node 13 is `A.process`; node 34 is `B.process`.

### Important result
No engine change was needed for simple TypeScript parameter narrowing. The existing PHP AST contract already has a parameter type slot, and the existing call-resolution machinery consumes it sufficiently to resolve the typed receiver. The portability work belongs in the frontend adapter: preserve language type facts in the neutral/legacy representation rather than teaching the engine TypeScript syntax.

## Conservative behavior
The union annotation is not converted into a fake exact edge. The sidecar preserves it as `AMBIGUOUS`, while the legacy engine simply has no hard `call2mtd` edge. Likewise a missing method remains `UNRESOLVED`.

## Gate status
**PASS.** TypeScript type information demonstrably narrows a dynamic method call from ambiguous to exact in the real engine, with no PHP-engine behavior change.

## Next useful gate
Property/field provenance and typed object flow, e.g.:

```ts
class Holder { worker: A; }
function f(h: Holder, x: string) {
  return h.worker.process(x);
}
```

That tests whether type information survives one property dereference rather than only a directly typed parameter.

## Gate 3 regression
The updated adapter was rerun on the prior JavaScript Gate-3 fixture. Resolution semantics are unchanged (the only textual difference is a `basis` description), and the real engine still reports the same exact edges:

```text
EDGE 59 -> [13]
EDGE 87 -> [13]
```

So adding TypeScript parameter-type emission did not regress the existing JavaScript class/method behavior.
