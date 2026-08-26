# Gate 10 — receiver-sensitive state-summary IR

## Goal
Introduce the smallest language-neutral state abstraction needed to connect an exact property write to a later exact property read without using global property-name taint.

The legacy-engine baseline from Gate 9 is preserved as a control. With exact call-resolution edges present, it still reports receiver-only return dependence for stateful cases and cannot distinguish a source write from a constant write.

## Fixture
Gate 10 tests seven cases over `A.value` / `A.other` and `Holder.worker`:

1. `topState`: interprocedural `store(h, source)` then `load(h)`.
2. `topConstantOverwrite`: source write followed by exact constant overwrite before load.
3. `directState`: same-function source write then read.
4. `directConstant`: same-function constant write then read.
5. `differentField`: write `other`, read `value`.
6. `twoObjects`: write `a.value`, read distinct allocation `b.value`.
7. `sameObject`: write and read the same allocation's `value`.

## Legacy engine baseline
The real compiled engine runs on the Gate-10 CSV with the existing frontend call-resolution bridge. All twelve method calls are admitted as EXACT (`exact_edges_added=12`). Ordinary call edges also resolve.

Observed legacy return summaries include:

```text
RET 137 topState              params=[h, source] positions=[0]
RET 168 topConstantOverwrite  params=[h, source] positions=[0]
RET 206 directState           params=[h, source] positions=[0]
RET 239 directConstant        params=[h, source] positions=[0]
RET 271 differentField        params=[h, source] positions=[0]
RET 304 twoObjects            params=[source]    positions=[]
RET 342 sameObject            params=[source]    positions=[]
```

This reproduces the Gate-9 boundary: exact call resolution is not sufficient to carry heap/property state.

## State-summary IR
Gate 10 adds a frontend-side prototype with the following neutral summaries:

```text
A.setValue:  WRITE THIS.value <- PARAM0
A.setOther:  WRITE THIS.other <- PARAM0
A.readValue: RETURN STATE(THIS.value)
A.readOther: RETURN STATE(THIS.other)

store:       WRITE PARAM0.worker.value <- PARAM1
load:        RETURN STATE(PARAM0.worker.value)
```

State identity is **receiver identity + property path**. Distinct allocation sites and distinct property names are never merged. A later exact write to the same state key overwrites the previous exact value.

## Run result
The state model executes the actual Gate-10 TypeScript fixture and reports:

```text
topState              -> PARAM:topState.source
topConstantOverwrite  -> CONST:"CONST"
directState           -> PARAM:directState.source
directConstant        -> CONST:"CONST"
differentField        -> STATE_UNKNOWN(...worker.value)
twoObjects             -> STATE_UNKNOWN(...b.value)
sameObject              -> PARAM:sameObject.source
```

`gate10_test.py` passes **7/7**.

The two negative controls are the important anti-false-flow checks:

- writing `other` does not taint/read `value`;
- writing `a.value` does not flow into a distinct `new A()` allocation `b.value`.

The constant-overwrite test also demonstrates a kill: an exact later `CONST` write replaces the earlier source value.

## Status

- exact receiver + same property state flow: PASS
- interprocedural state effect (`store` -> `load`): PASS in state-summary prototype
- constant overwrite kill: PASS
- same receiver + different property isolation: PASS
- distinct allocation + same property isolation: PASS
- legacy-engine call resolution: PASS / EXACT
- legacy-engine native heap/property provenance: NOT MODELED
- security source/sink semantics added: NO

## Architectural conclusion
The next portability abstraction is now concrete rather than hypothetical. It does not need a global `propertyName -> taint` map. A narrow sidecar/IR can represent method/function state effects using receiver-relative locations such as `THIS.value` and `PARAM0.worker.value`, then instantiate those locations at an exact call site.

The remaining integration question is whether these state-summary facts should be consumed by the existing interprocedural provenance layer or by a small neutral state-flow layer immediately before it. Gate 10 deliberately does not inject them into the legacy hard DDG yet; it proves the identity/overwrite rules and alias controls first.
