# JS-PROV-R30 — preregistered BEFORE implementation

## Scope
INTEGRATION ONLY, exactly as JS-PROV-R25. `context_state_flow`'s callback
resolution consumes ESTABLISHED `ModuleExportIdentityFact` records. **R14/R25
semantics are NOT modified.** Producers frozen and hash-verified.

## Preregistered expectations — MECHANISM, not incidental totals
(K1's defect: an invariant that conflates a mechanism with a count will
eventually be violated by a correct change.)

```text
CORPUS B
  - the existing 33 callback facts remain IDENTICAL
  - the existing 23 state flows remain IDENTICAL
  - no previously established fact disappears
  - additional facts are PERMITTED only if each is newly enabled by an
    established ModuleExportIdentityFact AND independently verified against
    source

CORPUS D
  - L4 must rise above 0
  - L5 must rise above 0 IF the newly identified callbacks participate in the
    preregistered ctx.state.user flow
  - every new L4/L5 fact traceable to a ModuleExportIdentityFact
  - no module-export-ABSTAINED callback may move downstream
  - demonstrably wrong = 0
```

## Decisive negative control (R25-style)
```text
import OBSERVED, but ModuleExportIdentityFact = ABSTAINED
      -> callback identity MUST NOT establish
      -> state flow MUST NOT establish through that callback
```
This proves R30 consumes the semantic identity FACT, not the mere fact that a
controller was imported.

## Frozen
No validator (joi/zod/yup) work. Missing plumbing beneath validator semantics is
still being found; profiling validators now would be premature.
