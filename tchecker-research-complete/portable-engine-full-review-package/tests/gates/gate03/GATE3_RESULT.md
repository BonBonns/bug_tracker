# Gate 3 — JavaScript classes, methods, and dynamic dispatch

## Scope
No security rules. This gate tests whether the existing engine can ingest JavaScript class/method shapes and how exact vs dynamic dispatch behaves.

## Fixture
- `A.process(x) -> x`
- `B.process(x) -> "CONST"`
- `exact(input) -> new A().process(input)`
- `exactVar(input) -> { const a = new A(); return a.process(input); }`
- `ambiguous(obj,input) -> obj.process(input)`
- `unknown(obj,input) -> obj.missing(input)`

## Real-engine result
The joern-php engine accepted the JS-derived PHP-compatible CSV class/method AST. `PHPCGFactory.newInstance()` completed through call-graph construction in the probe.

Resolved engine edges:
- method-call node 59 (`new A().process`) -> method node 13 (`A.process`)
- method-call node 87 (`a.process`, where `a = new A()`) -> method node 13 (`A.process`)

No edge was manufactured for:
- node 110: `obj.process(input)` with unknown receiver type and two unrelated `process` implementations
- node 133: `obj.missing(input)` with no matching method

This is conservative behavior: exact receiver information resolves; dynamic receiver ambiguity remains unresolved rather than being flattened to a hard edge.

## Frontend resolution-quality sidecar
The companion `resolution_manifest.json` records what the JS frontend knows before the legacy engine loses that distinction:
- direct `new A().process` = `EXACT`, target `A.process`
- local `a = new A(); a.process` = `EXACT`, target `A.process`
- untyped `obj.process` = `AMBIGUOUS`, targets `{A.process, B.process}`
- `obj.missing` = `UNRESOLVED`

The legacy engine currently represents both the last two as absence of a `call2mtd` edge. That is the remaining portability seam: preserve `AMBIGUOUS` versus `UNRESOLVED` into the neutral analysis layer rather than inventing exact targets.

## What changed
Only the frontend adapter was extended. No PHP engine behavior was modified.

New adapter support:
- `AST_CLASS` with `TOPLEVEL_CLASS` wrapper
- `AST_METHOD`
- `AST_NEW`
- `AST_METHOD_CALL`
- class names on method nodes
- object-variable assignment from `new Class()`

## Next gate
TypeScript type annotations: show that `obj: A` can narrow the same syntactic `obj.process()` call from JS `AMBIGUOUS` to frontend `EXACT`, while keeping the same core resolution contract.
