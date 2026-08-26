# Gate 9 — cross-call object/property state provenance

## Goal
Test whether provenance survives a heap/property write followed by a later property read, rather than only argument/parameter/return flow.

Target state transition:

```ts
class A {
  value: string;
  setValue(v: string) { this.value = v; }
  readValue() { return this.value; }
}
```

Two forms were tested:

```ts
function store(h: Holder, input: string) {
  h.worker.setValue(input);
}
function load(h: Holder) {
  return h.worker.readValue();
}
function topState(h: Holder, source: string) {
  store(h, source);
  return load(h);
}
```

and a stronger same-function control:

```ts
function directState(h: Holder, source: string) {
  h.worker.setValue(source);
  return h.worker.readValue();
}
```

Constant controls write `"CONST"` instead of `source`.

## Adapter additions
Gate 9 extends the Gate-8 adapter only enough to represent ordinary state syntax:

- `this` -> `AST_VAR("this")`
- `lhs = rhs` -> `AST_ASSIGN(lhs, rhs)`

No security source/sink logic was added.

## Resolution result
The TypeScript frontend resolves every `h.worker.setValue(...)` and `h.worker.readValue()` call EXACTLY to class `A`.

The real engine receives hard edges through the existing frontend-resolution bridge:

```text
CALL 74  -> [17]   A.setValue
CALL 96  -> [35]   A.readValue
CALL 180 -> [17]   directState setValue
CALL 190 -> [35]   directState readValue
CALL 213 -> [17]   directConstant setValue
CALL 222 -> [35]   directConstant readValue
```

Therefore this is not a call-resolution failure.

## Provenance result
The engine sees the setter's local data dependence:

```text
DDG 21 -> 28 var=v
```

which is the setter parameter flowing into `this.value = v`.

But that property state is not summarized across the subsequent getter call.

Observed return summaries:

```text
RET 83  load           params=[h]        positions=[0]
RET 103 topState       params=[h,source] positions=[0]
RET 134 topConstant    params=[h,source] positions=[0]
RET 164 directState    params=[h,source] positions=[0]
RET 197 directConstant params=[h,source] positions=[0]
```

The crucial failure is `directState`: even with `setValue(source)` and `readValue()` adjacent in the same function and both calls EXACTLY resolved, the returned value is attributed to receiver `h`, not `source`.

The constant control has the same summary, confirming the engine currently cannot distinguish:

```text
h.worker.setValue(source); return h.worker.readValue();
```

from:

```text
h.worker.setValue("CONST"); return h.worker.readValue();
```

at return-provenance level.

## Gate status

- JS/TS assignment syntax represented: PASS
- `this.value = v` local DDG dependency: PASS
- setter method resolution: PASS / EXACT
- getter method resolution: PASS / EXACT
- ordinary function-call resolution: PASS
- write -> later read heap/property provenance: NOT MODELED
- source-vs-constant distinction across object state: FAIL (same returned provenance)
- false exact call edges introduced: NO
- security modeling added: NO

## Architectural conclusion
Gate 9 finds the next real portability boundary: **heap/property state summaries**.

The existing interprocedural core handles argument -> parameter -> return chains once exact call targets are available, but a mutating call currently has no language-neutral summary like:

```text
A.setValue(param0): writes this.value <- param0
A.readValue():      returns this.value
```

Without that state fact, the write and later read cannot be connected, even when receiver and method resolution are exact.

This should not be fixed by marking the getter return as dependent on every prior argument or by property-name-only global taint. The next gate should introduce a narrow state-summary sidecar/IR with explicit receiver/property identity, then test alias controls before integrating it into hard provenance.
