# JS-PROV-R33 — Attempted and REVERTED

**Outcome: the fix was implemented, broke two gates, and was fully reverted.
Nothing from R33 is in the engine.** All gates green at the reverted state:
`JS_PROV_R14=11/11`, `JS_PROV_R23B=33/33`, `JS_PROV_R12=28/28`,
`JS_PROV_R29=9/9`.

## What the adversarial fixture proved (and this stands)

Your shared-name control unmasked Defect A exactly as intended. Before any fix:

```text
outer.js   module.exports = { shared: outerShared, inner }
inner.js   module.exports = { shared: innerShared }
use.js     const ctrl  = require("./outer").inner    -> binding: ctrl  -> ./outer
           const whole = require("./outer")          -> binding: whole -> ./outer
```

`ctrl` and `whole` are recorded **identically**, despite denoting different
program entities. `outer.js` and `inner.js` both export `shared`, so a consumer
resolving `ctrl.shared` against that binding would return `outerShared` — a
**fabricated** identity. The fixture removes the naming coincidence that masks
this on Corpus D, and is preserved at `fixture/`.

## The fix, and why it was reverted

The selector was recoverable structurally — a 5th `selector` column on
`require_bindings.tsv` correctly distinguished the two:

```text
use.js  spec=./outer  local=whole       selector=<none>
use.js  spec=./outer  local=ctrl        selector=inner
use.js  spec=./outer  local=missingSel  selector=nope
```

Consumers were updated to skip selector-bearing bindings. Result:

```text
JS_PROV_R14   11/11 -> 4/11    BROKEN
JS_PROV_R23B  33/33 -> 21/33   BROKEN
```

Reverted rather than debugged under budget. The engine is at its prior
known-good state; the R33 diagnosis and fixture survive for a clean retry.

## Preregistered teeth — status at revert

```text
T1  `require("./outer").inner` must not bind to ./outer   ACHIEVED by the fix,
                                                          reverted with it
T2a never resolves to OUTER's same-named member           ACHIEVED (abstained)
T2b resolves to INNER's member                            NOT ACHIEVABLE in scope
T3  bare require unchanged                                ACHIEVED
T4  unresolved selection abstains                         ACHIEVED
T5  existing CommonJS facts identical                     NOT MET (gates broke)
T6  demonstrably wrong = 0                                held throughout
```

**T2b was a preregistration defect.** Resolving `ctrl.shared` to `innerShared`
requires following `outer.inner` to `./inner` — which is **Defect B**, which
R33 explicitly declared out of scope. I wrote a tooth that cannot be satisfied
within the milestone's own boundary. Same class as K1: a preregistered
condition that quietly depends on work the milestone excluded.

## A separate finding: R31 has an unrecorded Corpus-B delta

While diagnosing, Corpus B module-identity facts read **48** against R31's
recorded baseline of 45. This **survives the R33 revert**, so it is R31's, not
R33's — I initially misattributed it.

The additional facts are legitimate R31 output — object-literal export members:

```text
security.util.js                    member=generateSecureToken
services/email/email.service.js     member=sendForgotPassword
resources/account/*/index.js        member=register
```

R31's verdict verified *state flows* were identical (23) but did **not** check
module-identity facts, so a real +3 delta went unrecorded. The facts appear
correct; they are not verified against source here.

```text
ACTION: JS-PROV-R31's Corpus-B invariant is INCOMPLETE as recorded.
        Verify these members against source and amend R31's verdict.
```

# JS-PROV-R33 VERDICT

```text
STATUS:              ATTEMPTED, REVERTED. Nothing in the engine.
DEFECT A:            CONFIRMED and UNMASKED by the shared-name fixture --
                     `ctrl` and `whole` recorded identically while denoting
                     different entities; `shared` exists in both modules.
FIX FEASIBILITY:     DEMONSTRATED -- the selector is structurally recoverable.
REVERT REASON:       consumer update broke R14 (11->4) and R23B (33->21);
                     reverted rather than debugged under budget.
GATES AT REVERT:     R14 11/11, R23B 33/33, R12 28/28, R29 9/9 -- all green.
PREREGISTRATION:     T2b was unsatisfiable within the declared scope.
SIDE FINDING:        R31 Corpus-B module-identity 45 -> 48, unrecorded.
NEXT:                retry R33 with the same fixture; the likely break is that
                     three consumers read require_bindings.tsv and a column
                     change is a cross-cutting schema edit, not a local one.
                     Add the selector as a SEPARATE file rather than a new
                     column, so existing readers are untouched.
```

## Discipline note

Two things worth recording.

The revert was the right call and it was not free — the fix was close, the
diagnosis was sound, and the fixture proves the defect is real. But leaving four
gates red to preserve partial work would have traded a known-good engine for an
unverified one.

The more useful lesson is the *shape* of the break. `require_bindings.tsv` is
read by three separate consumers; adding a column changed a schema they all
share. That is the same coupling failure as the fixture-directory rule
(R26/R27/R29): a shared artifact edited as though it were local. A new fact
belongs in a **new file**, not a new column on a file others already parse.

---

# R33 RETRY — COMPLETED

**`JS_PROV_R33=8/8`.** All gates green: R07 31/31, R08 13/13, R09 12/12,
R12 28/28, R14 11/11, R17 18/18, R21 13/13, R23B 33/33, R29 9/9.
`PROMOTION_GATE=PASS`.

## The one change that made the difference

The first attempt added a 5th column to `require_bindings.tsv`. That file is
parsed by **three** independent consumers, so a column change is a cross-cutting
schema edit — it broke R14 (11→4) and R23B (33→21).

The retry emits the selector to a **separate file**,
`require_member_selection.tsv`. `require_bindings.tsv` is byte-compatible at 4
columns; existing readers are untouched, and a consumer opts in by reading the
new file.

```text
require_bindings.tsv        (UNCHANGED, 4 cols)
  use.js  ./outer  whole
  use.js  ./outer  ctrl
require_member_selection.tsv (NEW)
  use.js  ctrl        ./outer  inner
  use.js  missingSel  ./outer  nope
```

## Teeth

```text
T1  selector recovered for `require('./outer').inner`          PASS
T1  bare `require('./outer')` records NO selector              PASS
T2a SHARED-NAME CONTROL: ctrl never resolves against outer.js  PASS
T2a ctrl abstains entirely -- never fabricates                 PASS
T4  unresolved `.nope` abstains, no module fallback            PASS
T5  require_bindings.tsv schema unchanged (4 columns)          PASS
R33 selector in a SEPARATE file, not a new column              PASS
T6  no fact points at a module the local does not denote       PASS
```

`T2b` (resolve `ctrl.shared` to `innerShared`) remains **out of scope** — it
requires Defect B. The milestone delivers the soundness half only, as scoped.

## Corpora

```text
Corpus B  module-identity 48 (identical), validate() 9 (identical),
          L5 flows 23 (identical, all MUST)
          selector-guarded locals: 0  -- Corpus B has no `require(x).member`,
          which is why the defect was invisible there
Corpus D  guard fires on the REAL bindings:
            routes/articles-router.js  ctrl -> ../controllers  selector=articles
            routes/profiles-router.js  ctrl -> ../controllers  selector=profiles
            routes/tags-router.js      ctrl -> ../controllers  selector=tags
            controllers/*.js           joinJs -> join-js       selector=default
          L3 28, L5 0 (movement permitted, not required)
```

The false `ctrl -> ../controllers` bindings that R32 identified as a latent
fabrication are now refused rather than recorded.

# R33 FINAL VERDICT

```text
STATUS:            COMPLETE. Defect A closed.
SOUNDNESS:         a local bound by `require(spec).member` is no longer recorded
                   as a module binding; it abstains.
SCHEMA:            require_bindings.tsv unchanged; selector in a new file.
GATE:              JS_PROV_R33=8/8, own isolated fixture.
CORPUS B:          identical on every measure.
CORPUS D:          guard fires on 3 real router bindings + 3 controller ones.
OUT OF SCOPE:      T2b / Defect B -- resolving the selected member to its own
                   module. Separate revision.
```

## Discipline note

The retry took one structural change, and it was the change the failure itself
named: a shared artifact must not be edited as though it were local. That rule
now has four independent confirmations — R26, R27, R29 (fixture directories) and
R33 (a fact file with three readers).

Worth noting what the revert bought. The first attempt's diagnosis was correct
and its fix worked; only the delivery mechanism was wrong. Reverting cost the
implementation but preserved the fixture, the measurement, and the named cause —
and the retry reused all three. A revert that keeps the evidence is cheap; the
expensive thing would have been keeping four gates red while trying to debug a
cross-cutting edit.
