# JS-PROV-R29 — Direct-Receiver Framework Registration

`JS_PROV_R29=9/9`. All gates green; `PROMOTION_GATE=PASS`.
Fixes the limitation JS-PROV-R24 exposed on Corpus D.

## Change

`framework_registration.py` accepted receiver-domain evidence only for
**parameter** receivers. It now also accepts a receiver whose **own resolved
type** is in the framework profile.

The framework profile is unchanged as a concept — still a closed, curated
table. Only *which evidence source may satisfy it* changed. `koa-router` was
added alongside `@koa/router` as an **explicit second entry** (pre-fork package
name), never by normalising or fuzzy-matching specifier strings.

## Why this does not reintroduce the R09 hazard

R09 deliberately distrusted `recv_type` because jssrc2cpg mis-propagated types
onto **parameters** (`t:ts::program:FakeRouter` on every router param,
including the real one). That mis-propagation is interprocedural. A **direct
local** takes its type from its own initializer. Measured support:

```text
R07 fixture   direct -> @koa/router   (real, correct)
              fr     -> FakeRouter    (fake, correct)
Corpus D      router -> koa-router    (15/15, correct)
```

The parameter path is untouched and still uses `ObservedParameterTypeFact`.
`identity_evidence` distinguishes the two: `RECEIVER_DOMAIN_EVIDENCE` vs
`DIRECT_RECEIVER_TYPE`.

## Decisive negative control — passes

```text
const real   = new Router();      real.get(...)    -> ESTABLISH   (profiled)
const fr     = new FakeRouter();  fr.get(...)      -> nothing     (not profiled)
const objLit = { get(){} };       objLit.get(...)  -> nothing
const opaque = globalThis.what;   opaque.get(...)  -> nothing
exactly ONE registration in the fixture
```

`fr.get("/no", handler)` is syntactically identical to `real.get("/ok", handler)`.
Only the profile membership of the receiver's type separates them.

## Preregistered invariants

```text
K1  Corpus B unchanged at 14        DEVIATION -- see below
K2  Corpus D reaches 15             MET (15 router verbs: 7 get, 6 post, 2 put)
K3  non-profiled type yields 0      MET
K4  ANY-typed receiver yields 0     MET
K5  R09 fake-router controls abstain MET (js-prov-r09 12/12)
K6  evidence sources distinguished  MET
K7  methodFullName never consulted  MET
K8  WRONG = 0                       MET
K9  all gates green                 MET
```

### K1 deviation, recorded not waived

Corpus B went **14 -> 18** registrations. K1 was written expecting no change.

The parameter path is genuinely untouched: all 14 `RECEIVER_DOMAIN_EVIDENCE`
registrations are identical. The 4 additions are `app.use(...)` on a local typed
`koa`, newly visible through the direct path. Verified against source: Corpus B
contains **12** `app.use(` sites, of which 4 resolve and 8 abstain.

They are correct new facts, not a regression — L5 flows are unchanged at 23. But
an increase is still a deviation from a preregistered invariant, and K1 should
have been worded as *"the parameter-receiver path is unchanged"* rather than
*"Corpus B unchanged at 14"*. Recorded as a preregistration defect.

## JS-PROV-R24 re-run on Corpus D

```text
LAYER                        before R29   after R29   Corpus B
3 framework registration          0           28         18
4 callback identity               0            0         33
5 context state flow              0            0         23
demonstrably wrong                0            0          0
```

**Layer 3 now reproduces on a second, independently selected corpus** — 15
router registrations plus 13 `app.use`. Layer 3 portability: two corpora.

**Layer 5 is still 0**, with a single new cause:

```text
23 abstentions, all WRITER_IDENTITY_UNKNOWN_OR_STUB
```

Corpus D's callbacks are imported controller functions
(`require('../controllers/…')`), so callback identity needs the module-export
path that R14/R25 built — it is not currently consulted by
`context_state_flow`'s callback resolution. Same shape as R23c's finding: a
correct producer that a consumer does not read.

Corpus D does have genuine cross-middleware state (`ctx.state.user` written in
`middleware/user-middleware.js`, read in 3 controllers), so the opportunity is
real and unexercised.

# JS-PROV-R29 VERDICT

```text
IMPLEMENTED:        direct-receiver registration, closed profile unchanged
GATE:               JS_PROV_R29=9/9 (own isolated fixture)
CORPUS D L3:        0 -> 28  (Layer 3 portability now TWO corpora)
CORPUS B:           parameter path unchanged (14); +4 correct app.use facts
DEVIATION:          K1 wording defect, recorded
STILL BLOCKED:      Corpus D L4/L5 -- callback identity does not consult
                    ModuleExportIdentityFact
NEXT:               JS-PROV-R30 -- wire ModuleExportIdentityFact into
                    context_state_flow callback resolution. Acceptance:
                    Corpus D L4/L5 > 0 with 0 wrong; Corpus B unchanged at
                    33 callbacks / 23 flows; all gates green.
```

## Discipline note

Two process points.

First, the R29 fixture initially went into the **js-prov-r09** gate directory.
Merging it into that gate's CPG broke four unrelated assertions — two files each
declaring `FakeRouter`, a short-name collision perturbing type recovery. This is
the third time fixture merging has produced a misleading gate state (R26, R27,
here). R29 got its own isolated gate instead. The rule now has three
independent confirmations: **one fixture set per revision, never merged.**

Second, K1's wording. The invariant said "Corpus B unchanged at 14" when the
intent was "the parameter path is unchanged". The result satisfied the intent
and violated the letter, and only checking the 4 new facts against source
established which. A preregistered invariant that conflates a mechanism with a
count will eventually be violated by a correct change.
