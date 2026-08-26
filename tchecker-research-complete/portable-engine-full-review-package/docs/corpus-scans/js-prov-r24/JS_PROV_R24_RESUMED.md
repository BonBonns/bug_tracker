# JS-PROV-R24 — RESUMED AND COMPLETED (negative result)

R24 was BLOCKED for want of an eligible corpus. One was found under the
**original, unmodified E1–E7 criteria**. The experiment ran. **The Koa chain did
not reproduce.**

## Corpus D — eligibility verified against the original criteria

```text
REPOSITORY : github.com/gothinkster/koa-knex-realworld-example
COMMIT     : 602e234139c453825eb3939cf24bdf00fc164e0e  (2021-09-06)
36 JS files / 1,795 LOC

E1 application, not a library      package.json: koa dependency, app entry
E2 koa-router present              require("koa-router") x5
E3 >= 8 route registrations        15
E4 >= 1 multi-callback route       8
E5 cross-middleware ctx state      ctx.state.user WRITTEN in
                                   middleware/user-middleware.js, READ in 4
                                   other files  (ctx.body/ctx.status were
                                   rejected as response writes, not state)
E6 CommonJS                        131 require / 31 module.exports / 0 ESM
E7 independently authored          gothinkster; not paralect, not a fork
```

## Result — frozen chain, no implementation changes

```text
LAYER                          Corpus D    Corpus B (baseline)
1 module/export identity            49      45
2 returned-function identity         0       2
  ObservedParameterType             52 (30 established)
3 framework registration             0      14      <-- DID NOT REPRODUCE
4 callback/middleware identity       0      33
5 context/property state flow        0      23
6 external input origin              0       0
demonstrably wrong                   0       0
```

**Layer 1 reproduced** — 49 CommonJS module-identity facts on an independent
corpus, so that layer now has genuine two-corpus evidence.

**Layer 3 produced nothing, and everything below it is blocked as a
consequence.**

## Cause — a previously recorded but never exercised scope boundary

```text
Corpus D:  const router = new Router()
           15 registration sites, receiver `router`, type = koa-router, isParam = NO

framework_registration.py:78
           if not param_method:   # receiver is not a parameter -> not our case
```

The receiver's framework type is **correctly resolved** (`koa-router`). R09
simply never looks at it, because R09 consumes *receiver-domain evidence for
parameter receivers* — the mechanism built for Corpus B, where routers cross
module boundaries as function arguments.

This exact limitation was recorded in **JS-PROV-R10**:

> *"`framework_registration.py` only handles receivers that are PARAMETERS. A
> directly-registered local router yields zero registrations. Corpus B is
> entirely parameter-shaped so R09 never exercised it."*

It was recorded and never exercised. Corpus D exercises it.

## Interpretation

This is a **clean abstention, not a wrong answer** — 0 registrations, 0 wrong
evidence. But the preregistered success criterion was:

> same semantic conditions -> same facts

Corpus D presents the same semantic condition (Koa router registrations) in a
different syntactic shape, and the facts did not follow.

```text
Koa chain portability : FAILS on a second corpus, for a named reason
Layer 1 portability   : ESTABLISHED on two corpora
Abstention safety     : holds (3 corpora)
```

## What would fix it

R09 should accept a receiver whose **own resolved type** is in the framework
profile, not only one whose type arrives via `ObservedParameterTypeFact`. The
evidence is already present and correct (`type = koa-router`); only the
consumer's entry condition is too narrow.

That is a new revision, not an R24 edit. It requires its own preregistration
and its own negative controls — in particular, a directly-typed receiver whose
type is *not* in the profile must still produce nothing.

```text
NEXT: JS-PROV-R29 — direct-receiver framework registration.
      Acceptance: Corpus D L3 15/15 with 0 wrong; Corpus B unchanged at 14;
      a non-profiled directly-typed receiver still yields 0; all gates green.
```

# JS-PROV-R24 VERDICT

```text
EXPERIMENT STATUS:   COMPLETED (was BLOCKED). Criteria NOT relaxed.
CORPUS:              koa-knex-realworld-example @ 602e2341, E1-E7 all verified
RESULT:              NEGATIVE. Koa chain did not reproduce.
LAYER 1:             REPRODUCED (49 facts) -> two-corpus evidence
LAYER 3-5:           0, blocked by a named scope boundary (parameter-only
                     receivers), recorded in R10 and never exercised until now
WRONG EVIDENCE:      0
IMPLEMENTATION:      unchanged; frozen throughout
```

## Discipline note

The blocked experiment was worth resuming precisely because it produced a
negative. Had R24 been quietly dropped after the first search failed, the Koa
chain would still carry an implicit claim of generality that a single
differently-shaped corpus disproves.

It also validates keeping R10's recorded-but-unexercised limitation in the
ledger rather than discarding it as hypothetical. It was hypothetical for four
milestones. It is now the reason a whole chain produced nothing.
