# Gate 7 — interprocedural return type -> receiver -> method dispatch

## Goal
Test whether a TypeScript frontend resolution fact can survive a function-return boundary and drive exact method dispatch in the real legacy engine without teaching `ParseVar` TypeScript semantics.

## Fixture

```ts
function getWorker(h: Holder): A {
  return h.worker;
}

function runExact(h: Holder, input: string) {
  return getWorker(h).process(input);
}
```

Controls:

```ts
function getUnionWorker(h: UnionHolder): A | B { return h.worker; }
function runAmbiguous(h: UnionHolder, input: string) {
  return getUnionWorker(h).process(input);
}

function getUnknownWorker(h) { return h.worker; }
function runUnknown(h, input) {
  return getUnknownWorker(h).process(input);
}
```

## Frontend result
The Gate-7 classifier extends the Gate-5 type resolver with function return annotations. For a call expression used as a method receiver:

- `getWorker()` has return annotation `A`, so `.process()` is `EXACT -> A.process`.
- `getUnionWorker()` has return annotation `A | B`, so `.process()` is `AMBIGUOUS -> {A.process, B.process}`.
- `getUnknownWorker()` has no return annotation. Because two in-scope `process` implementations exist, the frontend conservatively reports `AMBIGUOUS -> {A.process, B.process}` rather than guessing one.

Manifest-to-engine bridge rows:

```
136  EXACT      13
164  AMBIGUOUS  13,34
191  AMBIGUOUS  13,34
```

Node identities:

- 13 = `A.process`
- 34 = `B.process`
- 69 = `getWorker`
- 86 = `getUnionWorker`
- 103 = `getUnknownWorker`
- 136/164/191 = outer method calls
- 137/165/192 = nested free-function calls used as receivers

## Real-engine run
With `WP_FRONTEND_CALL_RESOLUTION` enabled:

```
FRONTEND_CLASSES={AMBIGUOUS=2, EXACT=1}
RESOLUTION 136 EXACT targets=[13]
RESOLUTION 164 AMBIGUOUS targets=[13, 34]
RESOLUTION 191 AMBIGUOUS targets=[13, 34]
EDGE 136 -> [13]
EDGE 137 -> [69]
EDGE 165 -> [86]
EDGE 192 -> [103]
```

This is the key Gate-7 result. The engine independently resolves each nested ordinary function call (`getWorker`, `getUnionWorker`, `getUnknownWorker`) using its existing call resolver. The frontend bridge adds exactly one hard method edge for the exact return-typed receiver. Neither ambiguous receiver becomes a hard method edge.

With the bridge disabled:

```
FRONTEND_CLASSES={}
EDGE 137 -> [69]
EDGE 165 -> [86]
EDGE 192 -> [103]
```

The exact method edge `136 -> 13` disappears while the engine's native free-function edges remain, confirming the method edge comes only from the explicit frontend resolution fact.

## Gate status
- TypeScript return annotation -> receiver type: PASS
- nested free-function call -> real engine call edge: PASS
- returned receiver -> exact method target through bridge: PASS
- union-return ambiguity preserved: PASS
- unknown-return receiver does not manufacture an exact target: PASS
- gate-off preservation: PASS

## Important limit
This gate proves **type-driven call resolution across a function-return boundary**. It does not yet prove that the legacy engine itself propagates the runtime *value lineage* `h.worker -> getWorker return -> receiver -> process parameter`. The frontend uses the declared TypeScript return type to resolve the receiver; the next provenance gate should test the actual argument/parameter/return data path separately.

## Architectural result
The portable seam now works across a non-local receiver:

```
TypeScript declaration
  getWorker(...): A
        |
        v
frontend return-type fact
        |
        v
getWorker(...).process(...)
        |
        v
resolution = EXACT, target = A.process
        |
        v
frontend bridge
        |
        v
legacy call2mtd edge
```

No TypeScript-specific logic was added to `ParseVar`, and uncertainty remains outside the hard legacy call graph.
