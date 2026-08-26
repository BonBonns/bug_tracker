# JS-PROV-R23c — Frozen Downstream Replay + Accounting Reconciliation

**Strictly observational.** No semantic fixes, no wiring changes, no
re-export work — even where it visibly blocks recoverable chains. Frozen hashes
in `evidence/FROZEN_HASHES.txt`.

## 1. Downstream replay — nothing changed, for a concrete reason

```text
LAYER                          R22    R23c
1 module / export identity       0       0
2 returned-function identity     0       0
3 framework registration         0       0
5 context state flow             0       0
6 external input origin         20      20   (BODY 6 / QUERY 2 / PARAM 12)
```

**Nothing previously established changed. No new identity is demonstrably
wrong. And Layer 1/2 production did not occur.**

The cause is not semantic:

```text
consumer wiring check:
  files reading `import_bindings.tsv`  ->  import_binding_identity.py ONLY
  module_specifier_resolution.py       ->  still reads `require_bindings.tsv`
```

`ImportBindingIdentityFact` is currently a **standalone fact with no
consumer**. R23b validated the fact; it did not integrate it. The replay's
value is precisely that it made that distinction visible instead of letting
"R23b passed 9/9" imply the chain had moved.

Per the stated rule, no wiring was added during this run.

## 2. Accounting delta — demonstrated, and my hypothesis was wrong

R23b reported `79 source / 63 established` with a 16-binding delta against 13
recorded abstentions, and speculated the 3-binding discrepancy was "a counting
difference … barrel `index.ts` re-exports counted once in one and multiply in
the other."

**Measured, that is not the cause.** Explicit triple-by-triple diff:

```text
A) source relative named-member bindings : 79   (79 distinct triples)
B) producer relative IMPORT nodes        : 76   (76 distinct triples)
C) established (relative)                : 63

IN SOURCE BUT NOT OBSERVED BY PRODUCER (exactly 3):
   tag/tag.controller.spec.ts  ./tag.controller  TagController
   tag/tag.controller.spec.ts  ./tag.service     TagService
   tag/tag.controller.spec.ts  ./tag.entity      TagEntity

OBSERVED BY PRODUCER BUT NOT IN SOURCE: (none)
```

All three missing bindings are in **`tag/tag.controller.spec.ts`** — the single
file `jssrc2cpg` omits under its known test-pattern ignore, already recorded in
R22's frontend-validity check and documented since JS-REAL-R01. Nothing to do
with barrels.

The accounting now closes exactly:

```text
79 source  =  76 observed  +  3 in the omitted .spec.ts file
76 observed = 63 established + 13 abstained          (identity, verified True)
13 abstained = 9 EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION   (re-export gap)
             + 4 UNRESOLVED_MODULE_OR_NO_EXPORT_ASSIGNMENTS
```

**Corrected recall: 63 of 76 observable relative bindings (83%)**, not 63/79.
The 3 unobservable bindings are a frontend omission, not a producer miss, and
should not be counted against it.

## 3. Denominator note, retained

```text
63 / 220  = 29%   "what fraction of ALL import observations became identities?"
63 /  79  = 80%   "what fraction of independently establishable relative cases?"
63 /  76  = 83%   "...excluding bindings the frontend never exposed"
```

These are three different measurements, not competing versions of one metric.
The third is the producer's actual recall; the first is not a producer metric at
all, since 127 of its denominator are bare-package imports it must abstain on.

## 4. Re-export gap — parked, not promoted

9 of 13 relative abstentions are `export { x } from './y'`. That is the
dominant *abstention* reason but it does not block anything downstream, because
downstream has no consumer at all. It therefore remains parked, per the rule
that the next experiment stays about portability rather than turning back into
feature work.

# JS-PROV-R23c VERDICT

```text
DOWNSTREAM PRODUCTION CHANGE:  NONE. Layers 1-5 unchanged at 0; Layer 6
                               unchanged at 20 with identical families.
PREVIOUSLY ESTABLISHED FACTS:  UNCHANGED.
NEWLY WRONG IDENTITIES:        0.
CAUSE OF NO L1/L2 MOVEMENT:    ImportBindingIdentityFact has NO CONSUMER;
                               module_specifier_resolution.py still reads
                               require_bindings.tsv. Integration, not semantics.
ACCOUNTING DELTA:              CLOSED and DEMONSTRATED. 79 = 76 observed + 3
                               bindings inside tag/tag.controller.spec.ts, the
                               known jssrc2cpg .spec ignore. 76 = 63 + 13 exact.
                               My R23b hypothesis (barrel counting) was WRONG.
CORRECTED RECALL:              63 / 76 observable relative bindings (83%).
RE-EXPORT GAP:                 9 of 13 relative abstentions. PARKED.

NEXT MILESTONE:                JS-PROV-R24 — independent Koa corpus. The Koa
                               chain currently has abstention-safety evidence on
                               Corpus C but portability evidence on only ONE
                               corpus. R24 is what converts that. Wiring
                               ImportBindingIdentityFact into a consumer is a
                               separate, later, isolated revision.
```

## Discipline note

Third instance in this line of a plausible explanation being wrong when
measured. R12's module-level coincidence, R22's "ESM therefore unsupported",
and now R23b's "barrel counting difference". Each fit the observation; none
survived a direct check.

The pattern is specific enough to name: **the failures cluster on explanations
offered for numbers that were otherwise satisfying.** R23b passed 9/9 and had a
defensible 80% figure, so the 3-binding remainder got a hypothesis rather than a
measurement. Requiring the delta to be *closed arithmetically* — `79 = 76 + 3`,
`76 = 63 + 13` — is what surfaced it, and that is cheap enough to make routine.

The replay result is the other thing worth not glossing: 9/9 on a fact gate
says nothing about whether the fact reaches anything. Those are separate claims
and were kept separate here only because the replay was run.
