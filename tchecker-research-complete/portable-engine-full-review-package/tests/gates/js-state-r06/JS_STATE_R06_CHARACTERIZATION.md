# JS-STATE-R06 — Return-Contract Establishment Characterization

**Status: characterization only. No detector/precondition was implemented in
the engine. Nothing here changes JS-STATE-R02's actual behavior.** This
follows the same discipline JS-STATE-R01 set: characterize first, using real
Joern output, before writing any code.

Motivated directly by JS-REAL-R01's single false positive
(`routes/account.ts:1759`, a `Set`-dedup key template-string-coerced from
plain `bounce.email`/`bounce.createdAt` fields, checked by `seen.has(key)`)
and its adjudicated root cause: `RETURN_CONTRACT_NOT_ESTABLISHED`. Real
frontend used throughout (joern-cli, `codepropertygraph-domain-classes
1.7.70`, same install verified across every prior JS-STATE milestone).

## The question

JS-STATE-R02 flags a candidate when a guard condition checks a value produced
by a closed-set erasing transformation. It never checks whether the value
being transformed actually came from something that could carry a failure
state in the first place. Two candidate signals were characterized as
possible preconditions:

- **SIGNAL A (GUARD SHAPE):** is the guard condition's own top-level CALL a
  member of a closed set of failure-style comparison operators
  (`<operator>.instanceOf`, `<operator>.equals`, `<operator>.notEquals`,
  relational operators), rather than an arbitrary named method call? Purely
  structural — needs zero type information.
- **SIGNAL B (RETURN CONTRACT):** does the erasing transformation's own
  argument carry a `dynamicTypeHintFullName` (`type_hints.tsv`, already
  exported, originally built for a different purpose — union-receiver-type
  recovery for dispatch resolution in Gate 24-TS/JSTS-R01) that contains a
  top-level union (` | `)? Requires reading existing type facts, no new type
  inference.

## Fixture

`fixture/return_contract.ts` — one true-positive control (identical shape to
JS-STATE-R01's `case2`), the false positive reduced directly from the real
JS-REAL-R01 finding, and two deliberate isolation cases designed to separate
the two signals from each other:

- `truePositive_unionReturnInstanceofGuard` — union return, instanceof guard.
  Both signals should hold.
- `falsePositive_plainFieldDedupKey` — plain-typed object fields, `.has()`
  guard. Reduced from the real bug. Neither signal should hold.
- `isolation_guardShapeOnlyNoReturnContract` — plain scalar origin
  (`plainMath(): number`), but an `instanceof Error` guard anyway (contrived
  but structurally valid TypeScript). Tests whether SIGNAL A **alone** would
  wrongly still flag this.
- `isolation_returnContractOnlyNonComparisonGuard` — real union-returning
  origin (`create()`), but a `.has()`-shaped guard instead of a comparison.
  Tests whether SIGNAL B **alone** would wrongly still flag this.

## Results

All four cases produced a raw JS-STATE-R02 erasure candidate, unchanged
(confirming R02 itself needs no modification — this is purely about an
additional precondition layered on top).

### SIGNAL A (guard condition's own CALL name)

| Case | Condition CALL name | Failure-style? |
|---|---|---|
| truePositive | `<operator>.instanceOf` | YES |
| falsePositive | `has` | NO |
| isolation (guard-shape-only) | `<operator>.instanceOf` | YES |
| isolation (return-contract-only) | `has` | NO |

Cleanly and reliably distinguishes by guard structure. **This alone would
have caught the real JS-REAL-R01 false positive** — `seen.has(key)` is not a
comparison operator at all, so a guard-shape-only filter excludes it with
zero type analysis. It correctly still flags `truePositive`. It does **not**
exclude `isolation_guardShapeOnlyNoReturnContract` — confirming SIGNAL A
alone is insufficient on its own.

### SIGNAL B (dynamicTypeHintFullName at the transformation's argument)

| Case | Argument | Type hint | Contains union? |
|---|---|---|---|
| truePositive | `r` | `number \| Error\|\|\|Result\|\|\|...` | YES |
| falsePositive | `record.id`, `record.label` (field accesses, not identifiers) | *(no hint recorded — `type_hints.tsv` only covers IDENT/PARAM node kinds, not field-access expressions)* | NO |
| isolation (guard-shape-only) | `x` | *(no hint — plain, unambiguous `__ecma.Number`)* | NO |
| isolation (return-contract-only) | `r` | `number \| Error\|\|\|Result\|\|\|...` | YES |

Cleanly and reliably distinguishes by return-contract origin. Correctly
excludes `isolation_guardShapeOnlyNoReturnContract` (the case SIGNAL A alone
would have missed). Correctly still flags `isolation_returnContractOnly` (the
case SIGNAL A alone excludes for a different, also-correct reason).

**Compatibility check against the existing JS-STATE fixture (not just this
new one):** re-examined `case4b_nullSentinelErasedByCoercion`'s raw facts
(the `null`-sentinel erasure case from JS-STATE-R01/R02, already known to
have a broken `methodReturn.typeFullName` per R01's original
characterization). Its transformation argument (`r4b`, fed into `Number()`)
carries hint `"number | __ecma.Null|||..."` — **the union signal survives even
though the method-return-type fact it would have depended on is broken.**
This is a materially better result than the alias-name-based join R01's
original characterization proposed (which would have inherited that same
bug): reading the union from the argument's own use-site type hint sidesteps
the malformed-return-type problem entirely, because it doesn't route through
`methodReturn.typeFullName` at all.

### Combined (A AND B required)

| Case | A | B | Combined verdict | Matches intended classification? |
|---|---|---|---|---|
| truePositive | YES | YES | CANDIDATE | YES (real candidate) |
| falsePositive | NO | NO | excluded | YES (matches JS-REAL-R01's adjudication) |
| isolation (guard-shape-only) | YES | NO | excluded | YES (needed B) |
| isolation (return-contract-only) | NO | YES | excluded | YES (needed A) |

**Both signals are independently necessary; neither alone is sufficient.**
The two isolation cases were built specifically to prove this, not to
illustrate it after the fact — each isolation case fails exactly the signal
it was designed to isolate, and no other.

## Missing facts / limitations found

- `type_hints.tsv`'s `dynamicTypeHintFullName` is only populated for
  `IDENT`/`PARAM` node kinds in the current export (`export_ts_facts.sc`).
  Field-access expressions (`record.id`) never get a hint at all — which
  happened to produce the *correct* answer here (absence reads as "not
  established," which was right for `falsePositive`), but this is
  coincidental, not a designed guarantee. A field access on a genuinely
  union/nullable-typed field would also show no hint under the current
  export, and SIGNAL B would default to "not established" for it too — a
  **potential false exclusion** (missed true candidate) this characterization
  did not test for, since no fixture case exercises it. Flagged as an open
  question, not assumed safe.
- SIGNAL A's closed comparison-operator set was informally scoped here
  (`instanceOf`, `equals`, `notEquals`, relational) but not exhaustively
  enumerated or cross-checked against every operator JS/TS's CPG might use
  for a failure-style check (e.g. `typeof x === 'undefined'`-style checks
  lower to `<operator>.equals` already covered, but this wasn't separately
  verified against a fixture case here).
- Neither signal was tested against a genuinely ambiguous case: a value whose
  origin is a union type PLUS a non-comparison guard that *is* nonetheless a
  legitimate failure check (e.g., a custom `isError(x)` helper function
  called in the condition, rather than a built-in operator). Signal A would
  currently exclude this, possibly wrongly. This is a real, disclosed gap in
  SIGNAL A's closed-set design, not covered by this fixture.

## False-positive / false-negative risk if this were implemented as-is

- Implementing SIGNAL A alone would very likely reduce recall further on an
  already near-zero-recall detector (JS-REAL-R01: 1 candidate / 50,638
  calls) by excluding any legitimate custom-function failure guard
  (`isError(x)`, `hasFailed(result)`, etc.) — a real risk given real code
  very plausibly uses helper functions for this rather than bare
  `instanceof`.
- Implementing SIGNAL B alone would under-cover the `record.id`-shaped false
  positive class only by coincidence (absence-of-hint defaulting to
  "excluded"), not by a designed, verified rule — risky to rely on without
  first confirming field-access identifiers with a genuinely union-typed
  declared field also produce no hint (untested here).
- Implementing both together is the best-supported option from this
  characterization, but inherits both individual risks above, additively.

## Is this worth promoting to implementation?

**Conditionally, yes — narrower than a full fix, but real progress.**
Both signals are:
- Computable from facts that already exist in the exported pipeline (SIGNAL A
  needs nothing new at all; SIGNAL B needs no new export, just reading
  `type_hints.tsv`, which `failure_state_facts.py` does not currently
  consume).
- Independently verified as necessary via the two isolation cases, not
  assumed.
- Confirmed not to regress on the one known method-return-type bug already
  on record (`createN`'s malformed return type) — SIGNAL B is robust to it.

**Recommended narrowest sound next step, if promoted to implementation:**
require SIGNAL A only where it can be evaluated (the guard condition's own
call name is always available, no missing-data case) as a hard precondition,
and require SIGNAL B additionally only as a **positive-evidence gate**
(candidate survives only if a union hint IS found), while treating "no hint
recorded" as UNKNOWN/abstain rather than as proof of absence — given the
disclosed field-access blind spot above, defaulting an unhinted field access
to "exclude" is a *hope*, not a *proof*, and should not be silently promoted
to one. This keeps the same abstention discipline the whole JS-STATE family
has held since R01 ("UNKNOWN is not SAFE" — an unhinted field access being
excluded here is a design choice under uncertainty, not a demonstrated
safety fact, and should be labeled as such if implemented).

## What this does NOT resolve

This characterization does not touch JS-REAL-R01's other, more structural
observation: the near-zero raw candidate rate on real code (1/50,638 calls).
Neither signal changes recall upward — both are exclusionary filters, so at
best this raises precision on an already-rare event. Whether JS-STATE's
current detection shape (closed-set coercion + comparison guard, in one
function) is simply too narrow to catch most real failure-state-erasure bugs
remains open and is not addressed here.
