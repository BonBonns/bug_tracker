# JS-PROV-R24 — Independent Koa Corpus: BLOCKED (no eligible corpus found)

**Outcome: the experiment did not run.** Eligibility criteria were preregistered
before any candidate was inspected (`PREREGISTERED_CRITERIA.md`); no candidate
found within the search budget satisfies them. Criteria were **not** relaxed to
make a candidate fit.

## Preregistered criteria (recorded before searching)

```text
E1  Koa APPLICATION (not a library/middleware package)
E2  @koa/router or koa-router registrations present
E3  >= 8 route registrations
E4  >= 1 route with 2+ callback arguments (middleware chain)
E5  ctx.<property> written by one middleware, read by another
E6  CommonJS module style
E7  independently authored (not paralect/koa-api-starter or a fork)
```

## Screening log

| Candidate | routes (E3) | multi-cb (E4) | module.exports (E6) | ctx writes | verdict |
|---|---|---|---|---|---|
| `koajs/examples` | 2 | — | 23 | 39 | **FAIL E1, E3** (example collection) |
| `chenshenhai/koa2-note` | 5 | — | 43 | 69 | **FAIL E1, E3** (tutorial repo) |
| `hoosin/koa2-blog` | — | — | — | — | unavailable |
| `17koa/koa-blog` | — | — | — | — | unavailable |
| `lidian99/koa2-blog` | — | — | — | — | unavailable |
| `bfwg/koa-vue-notes-api` | — | — | — | — | unavailable |
| `hteppl/koa-api` | — | — | — | — | unavailable |

Two clonable candidates, both failing E1 and E3. Five further candidates were
not retrievable.

## The relaxation that was declined

`koa2-note` fails E3 at 5 routes against a threshold of 8. Lowering E3 to 5
would have let R24 "run" and produce numbers. That is precisely the failure
mode preregistration exists to prevent: a threshold moved *after* seeing which
candidate is available is not a threshold. It is also the same class of error
R23c named — accepting a convenient explanation for an otherwise satisfying
result.

## Non-qualifying observation (explicitly NOT the experiment)

`koa2-note` was run anyway, frozen, purely as a smoke observation. **These
numbers do not constitute portability evidence and must not be cited as R24
results.**

```text
L1 module/export identity : 0   (136 abstentions)
L2 returned-function      : 0
L3 framework registration : 0   (301 abstentions)
L5 context state flow     : 0
L6 external input origin  : 0
```

Zero across the board with zero wrong evidence — consistent with a tutorial
repo whose 5 routes register inline handlers rather than the module-crossing
middleware chains the Koa producers target. It tells us nothing about
portability because the corpus does not exercise the conditions.

This is exactly the Corpus-C situation the preregistration was written to avoid:
a run that measures **absence of opportunity** and could be mistaken for
absence of capability.

# JS-PROV-R24 VERDICT

```text
EXPERIMENT STATUS:      BLOCKED. No eligible corpus located.
CRITERIA RELAXED:       NO.
IMPLEMENTATION CHANGES: NONE. System remains frozen.
WRONG EVIDENCE:         0 (in the non-qualifying observation).

KOA CHAIN EVIDENCE STATUS -- unchanged and precisely stated:
    portability of the NestJS boundary producer : TWO corpora
    portability of the Koa chain                : ONE corpus (Corpus B)
    abstention-safety of the Koa chain          : TWO corpora (C, and the
                                                  non-qualifying koa2-note)

WHAT WOULD UNBLOCK:     A Koa application meeting E1-E7. Realistic sources:
                        (a) a private/industrial Koa service, if one is
                            available to the project;
                        (b) GitHub code search filtered on
                            `router.post(` co-occurring with `module.exports`
                            and a middleware-chain arity >= 3, rather than
                            repository-name search, which is what failed here;
                        (c) accept a same-family corpus and state the weaker
                            claim explicitly.
NEXT MILESTONE:         Either retry corpus selection with the code-search
                        strategy above, or proceed to the deferred
                        ImportBindingIdentityFact WIRING revision (R25), which
                        is independent of corpus availability and has a
                        concrete acceptance target from R23c: L1/L2 production
                        on Corpus C should become non-zero, with Corpus B
                        CommonJS results and all gates unchanged.
```

## Discipline note

A blocked experiment is a worse outcome than a passing one and a better outcome
than a fitted one. The available move was to drop E3 from 8 to 5, run
`koa2-note`, and report five layers at zero as "portability confirmed, clean
abstention" — which would have been true sentence by sentence and misleading as
a whole.

The preregistration cost one command to write and prevented that directly. It
is worth keeping as a standing requirement for corpus-based milestones, in the
same way the spec-vs-implementation re-read became stage 5 of the promotion
gate.
