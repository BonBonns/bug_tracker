# JS-PROV-R35 — Module-Alias Export Member Identity (Defect B)

**`JS_PROV_R35=11/11`.** All gates green: R07 31/31, R08 13/13, R09 12/12,
R12 28/28, R14 11/11, R17 18/18, R21 13/13, R23B 33/33, R29 9/9, R33 8/8.
`PROMOTION_GATE=PASS`.

## What was implemented

`export_member_alias.tsv` — a **new file**, emitting the RHS **identifier name**
of each object-literal export member. `module_exports.tsv` is unchanged at 7
columns; consumers opt in.

Resolution is gated on the **require binding**, not on "the RHS is an
identifier":

```text
member RHS identifier name
   -> is it a BARE require-bound local in this file?   (require_bindings.tsv,
                                                        minus R33's selectors)
      -> resolve its specifier to a file with exports
```

That condition is what leaves plain-function members untouched — the constraint
JS-PROV-R34 identified and that reasoning alone would have missed.

## Preregistered teeth — all pass

```text
P1  `module.exports = { leaf }` with `leaf = require('./leaf')` -> ./leaf   PASS
N1  SHARED-NAME CONTROL: leaf.js and other.js BOTH export `leafFn`,
    and they are genuinely different declarations
    (leaf.js::program:leafFn vs other.js::program:otherFn)
    -> the alias resolves via ./leaf and NEVER other.js                     PASS
N2  selector-bearing local abstains (R33 guard holds)                       PASS
N3  non-module member (`plain`) abstains                                    PASS
N4  plain-function member (`localFn`) NOT treated as a module alias         PASS
N4  ...and still resolves as an ordinary member                             PASS
N5  module_exports.tsv schema unchanged; alias in a separate file           PASS
N8  every alias target names a file present in the export table             PASS
```

N1 is load-bearing: `other.js` deliberately exports `leafFn` as an alias of
`otherFn`, so a guessed module link returns a **different declaration**, not
merely a different path. The fixture makes the fabrication detectable rather
than assuming it cannot happen.

## Corpus B — identical on ALL ENUMERATED layers

Per the JS-PROV-R31 amendment, the invariant now names the layers it covers
rather than checking one and implying the rest:

```text
L1 module-identity : 48  (48)
L3 registrations   : 18  (18)
L5 state flows     : 23  (23), all MUST
import-binding     :  0  (0)
validate() resolved:  9  (9)
```

## Corpus D — the real barrel resolves

```text
controllers/index.js:users     -> controllers/users-controller.js
controllers/index.js:tags      -> controllers/tags-controller.js
controllers/index.js:profiles  -> controllers/profiles-controller.js
controllers/index.js:articles  -> controllers/articles-controller.js
```

This is the exact barrel that blocked JS-PROV-R30 and JS-PROV-R31. Its members
now carry a correct module link instead of `controllers/index.js::program` — the
containing-file type R34 identified as a wrong record.

# JS-PROV-R35 VERDICT

```text
DEFECT B:        CLOSED. Module-alias export members carry a correct module
                 link, derived from the require binding.
FABRICATION:     the shared-name control proves the join is derived, not
                 guessed -- a guess returns a different declaration.
SCHEMA:          module_exports.tsv unchanged; alias in a separate file
                 (R33's lesson, fifth confirmation).
CORPUS B:        identical on all five enumerated layers.
CORPUS D:        all four barrel members resolve to their real controllers.
GATES:           R35 11/11; nine other gates unchanged; PROMOTION_GATE=PASS.

NOT YET DONE:    the alias fact is PRODUCED, not yet CONSUMED by
                 context_state_flow's callback resolution. Corpus D L4/L5
                 remain 0. That is the R23c/R30 pattern -- a correct producer
                 with no consumer -- and is deliberately a separate revision.

NEXT:            JS-PROV-R36 -- consume export_member_alias in callback
                 resolution, so `ctrl.get` (where `ctrl = require('../controllers').articles`)
                 reaches articles-controller.js:get. Note this ALSO needs
                 R33's selector to be RESOLVED rather than merely refused --
                 i.e. Defect A's T2b, still open.
```

## Discipline note

Two things this milestone did not do.

It did not wire the fact into a consumer. Corpus D L4/L5 are still 0, and
reporting R35 as "unblocking Corpus D" would be false — the same overstatement
R30 avoided.

It did not widen the rule to "member RHS is an identifier", which would have
been simpler and would have passed P1. `localFn` proves why: plain-function
members already resolve correctly, and a broader rule would have silently
changed records that were right. The narrow condition came from measurement
(R34), not from design intuition.

Worth noting the chain to get here: R30 (consumer correct, blocked upstream) ->
R31 (member identity, blocked upstream) -> R32 (two defects named) -> R33
(Defect A closed) -> R34 (Defect B is a *wrong* record) -> R35 (Defect B
closed). Four of those six produced no downstream movement, and each null
narrowed the cause.
