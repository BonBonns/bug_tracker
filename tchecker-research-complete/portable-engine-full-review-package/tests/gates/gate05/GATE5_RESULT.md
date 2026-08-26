# Gate 5 — TypeScript typed-property receiver flow

## Goal
Test whether TypeScript receiver precision survives one property dereference in the real legacy engine, without adding security rules or changing PHP-engine behavior.

## Fixture
Two unrelated classes expose the same method:

- `A.process(x) -> x`
- `B.process(x) -> "CONST"`

Two holder types declare a typed field:

- `Holder.worker: A`
- `UnionHolder.worker: A | B`

Four calls are exercised:

1. `typedProperty(h: Holder, input) -> h.worker.process(input)`
2. `untypedProperty(h, input) -> h.worker.process(input)`
3. `unionProperty(h: UnionHolder, input) -> h.worker.process(input)`
4. `missingMethod(h: Holder, input) -> h.worker.missing(input)`

## Frontend result
The TypeScript sidecar resolves the receiver chain structurally:

- `h: Holder -> worker: A -> process` = `EXACT`, target `A.process`
- untyped `h.worker.process` = `AMBIGUOUS`, targets `{A.process, B.process}`
- `h: UnionHolder -> worker: A | B -> process` = `AMBIGUOUS`, targets `{A.process, B.process}`
- `h: Holder -> worker: A -> missing` = `UNRESOLVED`

This demonstrates that the frontend can preserve type information through one property dereference.

## Legacy CSV adapter
The adapter now emits:

- TypeScript class property declarations as `AST_PROP_DECL -> AST_PROP_ELEM`
- runtime property reads as `AST_PROP(object, property-name)`
- the existing class/method/parameter structures from Gates 3–4

The legacy php-ast property-declaration schema has no dedicated property-type child. Therefore the TypeScript annotation (`worker: A`) is intentionally preserved in the frontend resolution sidecar rather than being stuffed into an unrelated PHP field.

## Real-engine result
The existing engine accepts and processes the property AST cleanly (`ROOTS=11`), but resolves **zero** method-call edges for the four property-receiver calls.

Diagnostic output for the three `*.process` receivers shows:

```text
Property identity: 87 -1::worker
Property identity: 112 -1::worker
Property identity: 138 -1::worker
```

The key fact is `-1::worker`: `ParseVar` recognizes the property name but cannot recover the receiver class for `h.worker`. Its `AST_PROP` logic only derives a concrete property class for `$this->prop`; a property on an arbitrary typed variable remains class `-1`.

Therefore Gate 5 does **not** pass as an engine-level exact-resolution gate.

## What this establishes
Gates 3–4 showed that direct receiver type facts can be represented in the legacy input contract and consumed by the engine. Gate 5 identifies the next real portability boundary:

> TypeScript can resolve `h: Holder -> h.worker: A`, but the legacy PHP engine loses that type fact at the `AST_PROP` boundary.

This is not a JavaScript parser problem and not a call-name problem. It is a type/provenance representation gap between the frontend and the legacy resolver.

The correct next architectural seam is to carry frontend resolution/type facts explicitly rather than inventing a PHP AST encoding for TypeScript property types.

## Gate status
- Frontend typed-property resolution: **PASS**
- CSV ingestion/property AST: **PASS**
- Real-engine typed-property method resolution: **FAIL (bounded, diagnosed)**
- False exact edges for ambiguous/unresolved cases: **0**

