# Identity-gap characterization (Step 3 — measurement only, guard unchanged)

Question: is `this.sanitizePayload` an isolated resolver limitation, or a systematic source of
unnecessary `CANDIDATE_OPEN` results? Measured two ways: a population scan of all transform calls,
and a precise analysis of the transforms actually blocking OPEN candidates.

## Buckets
    A  resolver identifies the transform (definition_resolution ESTABLISHED)   -> no identity gap
    B  resolver UNKNOWN + UNIQUE local callee body (trace-backed)              -> bridge candidate
    C  resolver UNKNOWN + MULTIPLE bodies share the name (ambiguous)           -> must stay unresolved
    D  resolver UNKNOWN + NO local body                                        -> must stay unresolved

## Population scan — all user-defined transform calls (context)
| CPG | calls | A | B | C | D | this. | obj. | bare/imported |
|---|---|---|---|---|---|---|---|---|
| customs.js + 123done      | 565 | 0  | 261 | 110 | 194 | 37 | 260 | 86 |
| emails.js + fxa-shared    | 536 | 11 | 171 | 29  | 325 | 0  | 363 | 49 |
| fixture                   | 4   | 2  | 2   | 0   | 0   | 0  | 0   | 4  |

The import-based definition resolver establishes identity for **near-zero** calls in method-heavy
code: 0 of 565 in customs.js, 11 of 536 in fxa-shared. Most transform calls are `this.`/`obj.`
member calls the import resolver cannot identify. **So the resolver gap itself is systematic**, not
specific to customs.js. (Caveat: population bucket B here uses a *unique-local-body-by-name* proxy,
which is a necessary but not sufficient condition for trace-backed identity — an upper bound on
bridgeability, not the strict "trace uniquely enters this callee.")

## Precise scan — transforms actually blocking OPEN candidates
| candidate | blocking transform | call form | resolver | bucket |
|---|---|---|---|---|
| customs.js sink 1145 (×3 origins) | `sanitizePayload` | this_method | UNKNOWN | **B** |
| fixture sink 1102 (clip, wrap)    | `clip`, `wrap`    | imported   | ESTABLISHED | A |

The fixture's transforms are import-resolved (bucket A) — its OPEN edge already resolves via an
accepted hint, so it is **not** in the guard-blocked population. Only customs.js is blocked by
`subject_transform == UNKNOWN`, and its blocker is bucket B (a `this.`-method with a unique local
body the property layer actually entered).

## Key statistic (current corpus)
Of **N = 3** OPEN-blocking transform origin-paths with `subject_transform == UNKNOWN`
(1 distinct transform, `sanitizePayload`, across 3 origins of one sink):
- **B (unique trace-backed callee) = 3**
- C (ambiguous) = 0
- D (no local body) = 0

**Candidate dispositions that would move if bucket B became an accepted identity proof: 1**
— customs.js sink 1145, currently `CANDIDATE_OPEN` blocked *only* by identity (its semantic edge
is already resolvable; the body-shown run answered TRANSFORMS_PROPERTY).

## Interpretation
- The **resolver coverage gap is systematic**: the import-based resolver identifies almost none of
  the `this.`/`obj.` transform calls that dominate real code. So `sanitizePayload` is representative,
  not a one-off.
- The **current candidate impact is small** because the corpus is thin (only fxa yields serialize
  candidates): exactly one OPEN candidate is blocked by it today. As the candidate set grows, the
  population scan implies many more would be affected.
- A trace-backed identity bridge would be **targeted, not a blanket relaxation**: bucket C
  (ambiguous, 110 + 29 calls) and bucket D (no body, 194 + 325 calls) would correctly remain
  unresolved. Only bucket B — a unique local body the trace actually entered — would be bridged.

## Recommendation (for review; NOT applied here)
The bridge appears warranted: it converts a systematic resolver blind spot (member-call identity)
into resolvable identity *only* where a trace uniquely pins the exact body, while leaving ambiguous
and bodiless cases unresolved. Per the plan, this is Step 4 (add trace-backed exact-callee identity
as a SECOND identity-establishment mechanism, with the invariant that it must uniquely identify the
exact body supplied to adjudication), followed by Step 5 (re-run customs + fixture/regression to
confirm only the intended disposition moves). The paired customs experiment and the acceptance
guard remain frozen and unchanged in this step.
