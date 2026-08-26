# Gate 8 — runtime provenance across return -> receiver -> method dispatch

## Goal
Move beyond Gate 7's type-driven call-resolution result and verify ordinary value lineage through the real legacy engine, without adding security sources/sinks.

Target chain:

```text
source
  -> topExact(source)
  -> runExact(input)
  -> A.process(x)
  -> return
```

The receiver is itself obtained across a function-return boundary:

```text
h -> getWorker(h) -> h.worker : A -> .process(...)
```

## Adapter correctness issue found and fixed

Before measuring provenance, Gate 8 exposed a real adapter bug inherited from Gate 2: the adapter emitted all `PARENT_OF` relations by globally reversing them. That satisfied the legacy interpreter's child-before-parent requirement, but it also reversed sibling order. As a result a source declaration such as:

```ts
function runExact(h: Holder, input: string)
```

was loaded internally as parameter order `[input, h]`.

Gate 8 replaces global reversal with **post-order AST edge emission while preserving `childnum` sibling order**. After the fix the real engine reports:

```text
runExact params=[h, input]
```

and DDG edges for property-return helper functions also appear correctly (`h -> return`). This is an adapter-only correction; no new PHP/legacy analysis behavior is required.

## Fixture

Core exact path:

```ts
function getWorker(h: Holder): A {
  return h.worker;
}

function runExact(h: Holder, input: string) {
  return getWorker(h).process(input);
}

function topExact(h: Holder, source: string) {
  return runExact(h, source);
}
```

Constant control:

```ts
function topConstant(h: Holder, source: string) {
  return runExact(h, "CONST");
}
```

Ambiguous control:

```ts
function topAmbiguous(h: UnionHolder, source: string) {
  return runAmbiguous(h, source);
}
```

## Run-verified result

The engine builds the expected call edges:

```text
CALL 136 -> [13]   // exact frontend bridge: .process -> A.process
CALL 137 -> [69]   // getWorker -> getWorker definition
CALL 219 -> [119]  // topExact -> runExact
CALL 244 -> [119]  // topConstant -> runExact
CALL 268 -> [147]  // topAmbiguous -> runAmbiguous
```

Return-taint summaries, mapped to the engine's now-correct parameter order:

```text
RET 13  process      params=[x]         positions=[0]
RET 69  getWorker    params=[h]         positions=[0]
RET 119 runExact     params=[h,input]   positions=[1]
RET 202 topExact     params=[h,source]  positions=[1]
RET 227 topConstant  params=[h,source]  positions=[]
RET 251 topAmbiguous params=[h,source]  positions=[0,1]
```

This is the key Gate-8 result:

- `A.process(x)` returns only `x`.
- therefore `runExact(h,input)` returns only `input`, **not the receiver `h`**.
- therefore `topExact(h,source)` returns only `source` across another function boundary.
- replacing `source` with the literal `"CONST"` produces an analyzed empty dependency set in `topConstant`.
- the unresolved/ambiguous dispatch control remains conservative (`[0,1]`) rather than being falsely narrowed.

The generated DDG also contains the local helper relationship:

```text
DDG 73 -> 81 var=h
```

for `getWorker(h) { return h.worker; }`, confirming the property-return helper is represented as depending on `h` locally.

## Gate status

- adapter preserves source parameter order: **PASS**
- `getWorker(h) -> return h.worker` local dependency: **PASS**
- exact frontend method edge -> callee return summary: **PASS**
- `runExact` result depends on `input` only: **PASS**
- second interprocedural hop `topExact(source) -> runExact -> A.process -> return`: **PASS**
- constant argument blocks caller-dependent provenance: **PASS**
- ambiguous dispatch remains conservative: **PASS**
- security sources/sinks added: **NO**

## Architectural result

Gate 8 verifies the first end-to-end, non-security provenance chain through the real engine that combines:

```text
TypeScript frontend type facts
      +
frontend EXACT-resolution bridge
      +
legacy call graph
      +
legacy return-taint summaries
```

The frontend is responsible for language-specific receiver resolution. The existing core can then propagate the ordinary argument/parameter/return lineage once an exact target is supplied.

## Important correction to prior gates

Gate 7's **call-resolution** conclusion remains valid, but the adapter's global edge reversal corrupted sibling ordering for multi-parameter functions. Gate 8 fixes that before using parameter positions as provenance evidence. Any future JS/TS provenance gate should use this post-order-preserving adapter, not the Gate-7 adapter verbatim.
