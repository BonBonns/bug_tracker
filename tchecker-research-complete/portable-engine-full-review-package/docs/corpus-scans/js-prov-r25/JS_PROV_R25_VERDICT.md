# JS-PROV-R25 — ImportBindingIdentityFact Consumer Integration

**Integration only.** R23b producer frozen and hash-verified. No semantic change
to either producer. Expectations preregistered before implementation
(`evidence/PREREGISTERED_R25.md`).

R23c established the defect precisely: a correct producer, dead-ended.

```text
ImportBindingIdentityFact  --produced correctly-->  [X no consumer]  module/export resolution
```

## Preregistered invariants — all held

```text
I1 R23b output hash-identical                     PASS (diff clean)
I2 Corpus B CommonJS unchanged                    PASS 45 facts / 9 validate()
                                                  resolutions, evidence label
                                                  REQUIRE_BINDING+EXPORT_ASSIGNMENT
I3 no default/namespace established via wiring    PASS
I4 the 13 R23b abstentions remain abstentions     PASS
I5 no member identity without an R23b record      PASS (moved ⊆ established)
I6 existing established origins never disappear   PASS (L6 still 20)
I7 WRONG                                          0
I8 movement reported by layer + traced            see below
```

## Decisive negative control — the point of the milestone

R23b **saw** five import bindings and deliberately established only two:

```text
R23b established : fDecl, fAliased
R23b abstained   : fDefault (default), ns (namespace), viaReexport (re-export)

downstream moved : fDecl, fAliased
abstained bindings that moved downstream : NONE
```

The consumer moves on the **established fact**, not on the presence of an
import. `ns` in particular is present in `cpg.imports` with a plausible-looking
entity `./lib:ns` — a consumer keyed on import presence would have carried it
downstream and fabricated a member. It does not.

## Corpus C — movement by layer, traced

```text
LAYER                        R23c    R25    predicted
1 module/export identity        0      9    RISE  (the consumer being wired)
2 returned-function             0      0    0     (no wrapper-returned middleware)
3 framework registration        0      0    0     (NestJS, no router registrations)
5 context state flow            0      0    0     (no Koa ctx middleware chain)
6 external input origin        20     20    20    (must not shrink)
```

All nine L1 facts carry `identity_evidence = ESM_IMPORT_BINDING_IDENTITY` and
`enabled_by_import_binding`, e.g.:

```text
User('id')  <-  {local: User, member: User, target: user/user.decorator.ts}
```

Each traces to the exact R23b record that enabled it.

**9 of 63 established bindings produced downstream facts.** That was
preregistered as the expected shape — the 63 are *available* identities, and
only those consumed at a call site become L1 facts. Reporting 63 as the
denominator of a success rate would misdescribe what the consumer does.

Layers 2/3/5 stayed at zero exactly as predicted, for reasons independent of
this wiring: Corpus C is NestJS and contains none of those structures. The
prediction was recorded in advance so a zero could not be reinterpreted
afterwards.

## Gate

```text
JS_PROV_R23B=17/17   (R23b's 9 producer teeth + R25's 8 consumer teeth)
JS_PROV_R14  = 9/9   unchanged
JS_PROV_R12  =28/28  unchanged
```

# JS-PROV-R25 VERDICT

```text
INTEGRATION:            IMPLEMENTED. L1 consumes ESTABLISHED
                        ImportBindingIdentityFact records where the CommonJS
                        require_bindings path supplies equivalent identity.
PRODUCER SEMANTICS:     UNCHANGED (both), hash-verified.
COMMONJS PATH:          UNCHANGED (Corpus B 45 facts / 9 validate()).
DECISIVE NEGATIVE:      PASS. Abstained bindings move nothing.
CORPUS C MOVEMENT:      L1 0 -> 9, all ESM-evidenced and individually traced.
                        L2/L3/L5 unchanged at 0 as predicted; L6 unchanged at 20.
WRONG EVIDENCE:         0.

R23b vs R25 -- kept separate, as they answer different questions:
    R23b: can ESM import identity be established correctly?      YES (9/9)
    R25:  does the architecture actually USE it?                  YES (0 -> 9)

DOMINANT GAP:           Re-export chains, still 9 of 13 relative abstentions
                        (R23a). Now visibly the binding constraint on further
                        L1 growth in Corpus C, but still parked.
NEXT MILESTONE:         R24 remains BLOCKED and is NOT renumbered around. Resume
                        it under the ORIGINAL E1-E7 criteria if an eligible Koa
                        corpus is obtained (GitHub code search on `router.post(`
                        + `module.exports` + middleware arity >= 3). Otherwise
                        the re-export hop is the next isolated revision.
```

## Discipline note

The number that would have been easy to lead with is 63. Only 9 of those
bindings became downstream facts, and a "9/63 = 14%" framing would have been
just as misleading in the other direction — the 63 are available identities,
not pending obligations. Preregistering "it is NOT expected that all 63 cause
downstream facts" removed the temptation to describe either number as a rate.

The `ns` case is the one that mattered. It is present, well-formed, and carries
an entity string that looks exactly like a real member. Every layer of this
integration had an opportunity to carry it forward, and the reason it stops is
that the consumer was keyed on R23b's established set rather than on the import
table. That distinction is invisible when everything passes, which is why the
negative control is the gate's load-bearing tooth rather than the positive one.

---

# R25 CLOSEOUT

All nine closeout criteria re-verified independently at closeout (not carried
forward from the implementation run):

```text
C1 producer frozen                    PASS  R23b hashes diff-clean
C2 consumer integration proven        PASS  Corpus C L1: 0 -> 9
C3 every new L1 fact traceable        PASS  9/9 carry enabled_by_import_binding
C4 negative control                   PASS  fDefault / ns / viaReexport remain
                                            downstream-abstained
C5 no regression                      PASS  R14 9/9, R12 28/28
C6 no collateral semantic movement    PASS  L2=0 L3=0 L5=0, L6=20
C7 demonstrably wrong                 0
C8 CommonJS behaviour unchanged       PASS  Corpus B 45 facts, all
                                            REQUIRE_BINDING+EXPORT_ASSIGNMENT
C9 measured limit recorded            9 of 63 available import identities were
                                      consumed downstream. 63 is NOT a target
                                      and NOT a success-rate denominator.
```

## Final verdict

> **JS-PROV-R25: PROMOTED.** `ImportBindingIdentityFact` is now consumed by
> module/export identity resolution. Corpus C L1 production increased from 0 to
> 9 exactly as preregistered, with every new fact traceable to an established
> R23b import identity. No R23b-abstained import produced downstream identity,
> including the namespace-import fabrication control. Existing CommonJS
> behaviour and all previously established facts remained unchanged;
> demonstrably wrong = 0. No further semantic changes are included in R25.

Frozen state tagged in `R25_FROZEN_STATE.txt` (component hashes + gate results
at closeout).

**Re-export handling is explicitly NOT in R25.** It remains 9 of 13 relative
abstentions and is now the visible constraint on further Corpus-C L1 growth,
but folding it in would have made R25 a semantics change wearing an integration
label. If pursued, it is a new isolated revision with its own producer freeze,
preregistration, and negative controls.

---

> ## PARTIALLY SUPERSEDED (annotated by JS-PROV-R28)
>
> **`DOMINANT GAP: re-export chains, still 9 of 13 relative abstentions` is
> CLOSED** by JS-PROV-R26. Corpus C: 63 -> 72 established; the only remaining
> abstention class is `UNRESOLVED_MODULE_OR_NO_EXPORT_ASSIGNMENTS` (external
> packages, correct by construction).
>
> R25's own result — L1 0 -> 9, every fact traced, negative control clean — is
> unchanged and remains current.
