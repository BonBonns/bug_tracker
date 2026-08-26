# JS-PROV-R22 — Second-Corpus Portability Replay

**No implementation changes.** Every producer run frozen; hashes recorded in
`evidence/FROZEN_HASHES.txt`. This is a post-promotion external-validity gate,
not a feature milestone.

## Corpus C — independently selected

```text
REPOSITORY : github.com/lujakob/nestjs-realworld-example-app
COMMIT     : c1c2cc4e448b279ff083272df1ac50d20c3304fa  (2021-01-18)
SHAPE      : 35 TS files, 1,174 LOC, 5 controllers, 6 services, 6 DTOs,
             2 pipes, multiple modules (article/profile/tag/user/shared)
MODULE STYLE: ESM — 137 `import`, 41 `export`, 0 `module.exports`, 2 `require`
```

Deliberately different from `truthy`: different author, different ORM, service
and DTO layering, and — critically — **ESM rather than CommonJS**, which
Corpus B used.

## Frontend validity

```text
files on disk 35   files with exported methods 34   omissions 1
omitted: tag/tag.controller.spec.ts
```

The single omission is a `.spec.ts` file — the known `jssrc2cpg` test-pattern
ignore documented since JS-REAL-R01. Expected, categorized, not a defect.

## Per-layer results

```text
                                produced  established  abstained  DEMONSTRABLY WRONG
1 Module / export identity           0          0         174           0
2 Returned-function identity         0          0           -           0
  ObservedParameterType             60         25           -           0
3 Framework registration             0          0         591           0
4 Callback / middleware identity     0          0           -           0
5 Context / property state flow      0          0           0           0
6 ExternalInputOriginFact           20         20           9           0
7 TransformInputOriginFact           0          0           -           0
```

**`demonstrably wrong = 0` at every layer** — the invariant that matters.

## Layer 6 validated against independent ground truth

```text
producer : HTTP_BODY 6   HTTP_QUERY 2   HTTP_PARAM 12   HTTP_HEADERS 0   = 20
source   : @Body 6       @Query 2       @Param 12       @Headers 0       = 20
```

Ground truth derived by grep over the source, independently of the producer.
**Exact match**, on a corpus never seen during R21's promotion.

```text
@User(...)  x9  ->  UNKNOWN, DECORATOR_NOT_IN_CLOSED_SET
```

All 9 abstained, none guessed — even though `@User` plainly carries
request-derived data in this application, exactly as `@GetUser` did in truthy.
The closed set held under a second, differently-named custom decorator.

`derived = 1` — the dataflow consumer fired on real code (it was fixture-only
in R21), and correctly reported `DATAFLOW_FROM_ESTABLISHED_ORIGIN` rather than
a fresh decorator fact.

## Failure categories — pre-registered, assigned

```text
EXPECTED_UNSUPPORTED   Layers 1,2       Corpus C is ESM; R14's producer is
                       (module identity) CommonJS-specific (`require` +
                                        `module.exports`). 174 clean abstentions,
                                        no fabricated resolutions.
EXPECTED_UNSUPPORTED   Layers 3,4,5,7   NestJS establishes origin at the
                       (Koa chain)      decorator boundary; there is no
                                        `router.post(...)` registration, no
                                        middleware context object, and no
                                        opaque validation transform to carry
                                        inputs through. 591 clean abstentions.
WRONG_EVIDENCE         none             0 at every layer.
FRONTEND_GAP           1 file           .spec.ts, known ignore.
```

Every zero above is a **clean abstention with a named cause**, not a silent
failure. A lower count than Corpus B is the expected and correct outcome: the
two corpora exercise different evidence chains by design.

# JS-PROV-R22 VERDICT

```text
IMPLEMENTATION CHANGES:   NONE. All six promoted facts run frozen.
CORPUS-SPECIFIC CHANGES:  NONE required.
DEMONSTRABLY WRONG:       0 at every layer.
MEANINGFUL FACTS:         20 established ExternalInputOriginFacts on
                          independently selected real application code,
                          matching source ground truth exactly.
ABSTENTION QUALITY:       765 abstentions, all attributable to a
                          pre-registered category; none fabricated.

PORTABILITY: PASS
  - existing promoted facts required no corpus-specific semantic changes
  - zero demonstrated false evidence
  - meaningful facts established on independent real application code

WHAT THIS DOES NOT SHOW:  The Koa-side chain (module identity, registration,
                          callback identity, state flow, transform inputs) was
                          NOT exercised — Corpus C is ESM NestJS and contains
                          none of those shapes. Layers 1-5 and 7 remain
                          validated on ONE corpus each. Portability of the
                          NestJS boundary producer is now two-corpus;
                          portability of the Koa chain is still one-corpus.

DOMINANT GAP:             ESM module identity. R14 resolves CommonJS only, and
                          ESM is the dominant modern style — 137 imports here
                          versus 2 requires. This is the highest-value next
                          target, ahead of validator semantics.
NEXT MILESTONE:           JS-PROV-R23 — ESM Export Identity, extending R13/R14's
                          characterization to `import`/`export`/`export default`.
                          Acceptance: Corpus C module identity > 0 with zero
                          wrong resolutions; Corpus B CommonJS results
                          unchanged; all gates unchanged. THEN a third corpus
                          exercising the Koa chain, and only last the curated
                          joi/zod/yup profile.
```

## Discipline note

The headline is that nothing broke — but the honest reading is narrower than
"the architecture generalizes." Corpus C validated **one** of seven layers on a
second corpus. The other six abstained cleanly, which is the correct behaviour
and is genuinely informative, but a clean abstention is not evidence that a
layer would work if exercised.

The most useful finding is the one that looks like a null result: **layer 1
produced nothing because the corpus is ESM.** Two real corpora in, the
CommonJS-only assumption baked into R13/R14 is now visible as a portability
limit rather than an implementation detail — and it was invisible on Corpus B,
which happened to be CommonJS throughout.

The `@User` result is the other quiet success: a second, differently-named
custom decorator hit the closed set and abstained, with no temptation-driven
special case added for it.

---

> ## DIAGNOSIS CORRECTED (annotated by JS-PROV-R28)
>
> R22 attributed Layer-1's zero to *"Corpus C is ESM; R14's producer is
> CommonJS-specific"*. **JS-PROV-R23a measured this and it is wrong**:
> `jssrc2cpg` lowers ESM exports into exactly the `exports.X = Y` assignments
> R14 already reads. The real cause was an **import-binding** gap
> (`local = require(spec).member`), closed by R23b/R25.
>
> R22's measurements and its `PORTABILITY: PASS` stand. The causal attribution
> in the failure-category table does not.
