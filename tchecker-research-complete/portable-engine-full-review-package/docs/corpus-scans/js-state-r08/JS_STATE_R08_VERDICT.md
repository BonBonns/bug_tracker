# JS-STATE-R08 — Positive-Example Corpus Construction

**No engine changes.** R07 was run unchanged (hash `b18bc7aa…6d4d309`). No
exception semantics, guard operators, or coercion semantics were added.

Research question: **can R07 detect a real known instance of the bug family it
was designed to model?** Measured, not assumed.

---

## Priority 1 — Historical vulnerability replay

### Search scope and outcome

Public CVE/advisory/patch history was searched for JS/TS bugs combining a
`value | failure` return with a coercion before the failure check, prioritising
authentication/authorization/identity/session/token consequences. Most results
matched on *prose* ("type coercion", "authentication bypass") but not on
*mechanism*. Per instruction, prose matches were not accepted — the one
candidate whose advisory described a concrete coercion mechanism at a named
file and line was taken to source.

### Candidate 1 — source-confirmed, replayed

```text
PROJECT:              the-hideout/tarkov-data-manager
CVE/ADVISORY:         CVE-2026-21854 / GHSA-r8w6-9xwg-6h73 (CVSS 9.8)
VULNERABLE COMMIT:    188f756272e454490d667ddc3265645348701de7
FIXED COMMIT:         f188f0abf766cefe3f1b7b4fc6fe9dad3736174a
LANGUAGE:             JavaScript (.mjs, ES modules)
SOURCE AVAILABLE:     YES — cloned, both commits extracted and verified
```

**Verified vulnerable source** (`src/tarkov-data-manager/index.mjs:192`, read
from the actual commit, not from the advisory text):

```js
const users = { "admin": process.env.AUTH_PASSWORD };
// ...
if (users[username] && users[username] == password) {
    req.session.loggedin = true;
```

The fix diff is a single character-pair change, `==` → `===`.

```text
RETURN CONTRACT:      Object property lookup `users[username]`. Returns the
                      admin password string on success; returns
                      Object.prototype (an INHERITED property, truthy) when
                      username = "__proto__". A real success/failure value
                      distinction, but NOT a declared or annotated union
                      return from a function.
FAILURE REPRESENTATION: Inherited prototype object rather than a sentinel or
                      Error — the "failure" value is truthy, which is what
                      defeats the `users[username] &&` pre-check.
TRANSFORMATION:       NONE as a separate step. The coercion
                      (Object.prototype -> "[object Object]") happens INSIDE
                      the `==` abstract-equality algorithm itself.
LATE GUARD:           The guard IS the coercion site. There is no intermediate
                      transformed local.
SECURITY CONSEQUENCE: Full unauthenticated admin access with a valid session
                      cookie. Genuine, severe, and exactly the sink class R07
                      targets (session creation / privilege assignment).
```

### Replay result — R07 run unchanged on both commits

Frontend health on both: 275 methods, 3,216 calls, clean parse, exit 0.
`.mjs` was parsed correctly — **no frontend gap**.

| | vulnerable | fixed |
|---|---|---|
| Raw ERASES facts | **0** | 0 |
| R07 facts | 0 | 0 |
| R07 candidates | **0** | 0 |

**R07 MISSED the known vulnerable version.** Not forced, not explained away.

### Exact missing semantic fact (from the CPG, not from reasoning)

The CPG for line 192 contains:

```text
<operator>.indexAccess   users[username]              <- value producer
<operator>.equals        users[username] == password  <- guard AND coercion site
```

R07's chain requires: *a transformation call from the closed erasing set →
result assigned to a local → an independent guard checks that local.* Here:

- The value producer is `<operator>.indexAccess`, which is **correctly** not
  in the erasing set (index access performs no coercion).
- No closed-set coercion call is applied to the value at all.
- The coercion is **implicit, internal to the comparison operator's own
  semantics**, so no intermediate transformed local ever exists for a guard to
  check.

Notably, R07's **Signal A would have been satisfied** — `<operator>.equals` is
in its closed guard set. The chain failed at stage one (ERASES), not at either
R07 precondition.

```text
CLASSIFICATION: OUT_OF_MODEL
```

Specifically: *implicit coercion internal to a comparison operator*, versus
R07's model of *an explicit transformation that erases failure state before an
independent guard*. These are genuinely different bug shapes. Extending R07 to
cover it would mean modelling `==`'s abstract-equality semantics — which is
neither a new coercion nor a new guard operator, but a new **bug family**, and
is explicitly out of scope for R08.

---

## Priority 2 — Idiom-targeted corpus search + acceptance gate

The acceptance gate was applied to the tarkov corpus (a real, non-trivial
2,207-line authenticating application) before accepting it as an evaluation
corpus:

| Gate ingredient | Measured |
|---|---|
| `TRANSFORMATION_ON_RETURNED_VALUE` (erasing-set calls) | 102 (all `<operator>.formatString`) |
| `FAILURE_STYLE_GUARD` (Signal A closed set) | 19 |
| `FAILURE_CAPABLE_RETURN` (failure-capable union type hints) | **0** |

```text
CORPUS DECISION: REJECTED as an R08 evaluation corpus.
REASON: FAILURE_CAPABLE_RETURN = 0. R07 cannot establish a return contract
        anywhere in this corpus, so it cannot produce a candidate regardless
        of whether the bug is present. Accepting it would measure nothing.
```

**This rejection exposed the most important structural finding of R08**, which
generalises well beyond this one repository:

> **Signal B is a TypeScript-dependent signal.** It reads
> `dynamicTypeHintFullName`, which Joern's JS type recovery populates richly
> from TS annotations and only sparsely from plain JS.

Cross-corpus evidence for that claim:

| Corpus | Language | Failure-capable union hints |
|---|---|---|
| mozilla/fxa | 126 TS / 72 JS | present (union hints incl. `number \| Error`, `number \| __ecma.Null`) |
| node-oauth2-server | 0 TS / 38 JS | 11 |
| tarkov-data-manager | 0 TS (plain .mjs) | **0** |

On a plain-JavaScript corpus, R07's recall approaches zero **structurally** —
not because the bug is absent, but because the evidence Signal B requires is
not recoverable. Since a large fraction of real-world security-relevant Node.js
code is plain JS, this is a material limit on R07's applicability that neither
JS-REAL-R01 nor R02 could reveal (R01's corpus was TS-heavy; R02's had zero
candidates for an unrelated reason).

---

## Preserved separately — exception idiom

Per instruction, not folded into R07:

```text
EXCEPTION_FAILURE_IDIOM
```

- `node-oauth2-server` (JS-REAL-R02): 157 `throw new …Error` statements, zero
  error-returning functions.
- `tarkov-data-manager` (this milestone): same `throw`-based idiom.

Both projects represent failure via `throw`/`catch` rather than a returned
union. An exception-state-erasure analysis (e.g. a caught error coerced before
an `instanceof` check in a `catch` block) remains a **separate future
characterization track**, deliberately not started here.

---

# JS-STATE-R08 VERDICT

```text
historical candidates examined:   1 taken to source (CVE-2026-21854 /
                                  GHSA-r8w6-9xwg-6h73, tarkov-data-manager).
                                  Several further advisories surfaced by search
                                  matched on prose ("type coercion",
                                  "authentication bypass") but were not
                                  source-confirmed and are NOT counted.

source-confirmed matching bugs:   0 matching R07's model.
                                  1 source-confirmed real coercion-based auth
                                  bypass, but its mechanism is coercion INSIDE
                                  the comparison, not erasure BEFORE the guard.

vulnerable/fixed pairs available: 1 (188f7562 -> f188f0ab), both extracted,
                                  both scanned.

R07 true-positive replays:        0

R07 misses:                       1, classified OUT_OF_MODEL. Missing fact
                                  identified exactly from the CPG: no
                                  closed-set transformation call and no
                                  intermediate transformed local exist; the
                                  coercion is internal to <operator>.equals.
                                  R07's Signal A WOULD have matched; the chain
                                  failed at stage one (ERASES).

out-of-model cases:               1 (above), plus 2 corpora recorded as
                                  EXCEPTION_FAILURE_IDIOM (node-oauth2-server,
                                  tarkov-data-manager).

accepted positive-example corpora: 0. tarkov-data-manager was measured against
                                  the acceptance gate and REJECTED
                                  (FAILURE_CAPABLE_RETURN = 0).

RECALL EVIDENCE:  STILL ZERO. R07 has now been run against three real corpora
                  (fxa, node-oauth2-server, tarkov-data-manager incl. a known
                  9.8-severity auth bypass at its vulnerable commit) and has
                  never produced a true positive on real code. Its only
                  demonstrated true-positive behaviour remains synthetic.
                  This is now a measured result, not an open question.

DOMINANT MISSING FACT:  **Failure-capable return-contract evidence on plain
                  JavaScript.** Signal B depends on TypeScript-derived type
                  hints; on plain-JS corpora it measures 0-11 and on the one
                  corpus containing a real coercion auth bypass it measured
                  exactly 0. Secondary: the modelled bug shape itself
                  (explicit erasing transformation before an independent
                  guard) has not been observed even once in three real
                  corpora, while two adjacent shapes (implicit coercion
                  inside a comparison; exception-based failure) were observed
                  repeatedly.

NEXT MILESTONE:   **JS-STATE-R09 — Bug-Family Re-Scoping Characterization**
                  (characterization only, no implementation).

                  R08 answered the recall question, and the answer is that the
                  modelled shape may simply be rare in real JS/TS. Before any
                  further detector work, characterize which failure-state
                  erasure shape actually occurs in the wild, using the three
                  observed candidates as the starting taxonomy:
                    (a) explicit-coercion-before-guard  (R07's current model;
                        0 real instances observed in 3 corpora)
                    (b) implicit-coercion-inside-comparison  (1 confirmed
                        real CVE, severity 9.8)
                    (c) exception-idiom failure state  (2 corpora, dominant
                        real-world idiom)
                  Then decide from evidence whether R07 should be retained as
                  a narrow detector, re-scoped toward (b), or paralleled by a
                  separate (c) track. Do NOT tighten or broaden R07 until that
                  characterization exists.
```

## Discipline note

R08 was designed to find a positive example and did not find one — that is a
result, not a failure of the milestone. The valuable outputs are: a
source-verified vulnerable/fixed pair now permanently available for replay; an
exactly-characterized miss (OUT_OF_MODEL, with the missing fact identified from
the CPG rather than inferred); and a newly measured structural limit (Signal B's
TypeScript dependence) that reframes R07's applicability. The temptation to
extend R07 to cover the one real CVE found — a one-line change to accept
`<operator>.equals` as its own coercion site — was deliberately not taken,
because that would be fitting the detector to a single example, which is the
exact failure mode the last four milestones were structured to avoid.
