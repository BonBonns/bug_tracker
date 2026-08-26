# Step 4 — trace-backed exact-callee identity (second identity mechanism) + Step 5 regression

## Invariant (implemented)
    transform identity is ESTABLISHED iff either:
      1. the existing definition resolver establishes it (import binding -> module -> export -> body), OR
      2. the observed transform call is trace-linked to EXACTLY ONE callee body (via actual
         MethodParameterIn entry on the dataflow path), and that exact body is supplied to
         semantic adjudication.
    Anything ambiguous or bodiless stays UNKNOWN. No same-name inference; no this.foo() shortcut;
    no promotion from the population proxy.

## Producer: export_trace_identity.sc (new, parallel to the definition resolver)
For each transform call it collects the callee METHOD that OWNS each entered MethodParameterIn on
the flow path (actual trace entry, not a name lookup). Identity is emitted only when exactly one
distinct callee method is entered across all observed flows; the exact method body is emitted with
it. Ambiguous (multiple bodies) and no-entry calls emit unique=false -> no identity.

## Adjudicator wiring
subject_transform is resolved in priority order: definition resolver (ESTABLISHED) first; else
trace-backed identity when unique (def_status = ESTABLISHED_BY_TRACE, body = the traced body,
identity = TRACE:<callee.fullName>); else UNKNOWN. The acceptance guard is UNCHANGED
(HIGH confidence AND subject_transform != UNKNOWN); it now passes for trace-verified transforms.

## Step 5 regression (strict)
| case | expected | observed |
|---|---|---|
| customs.js + correct answer          | move -> RESOLVED_CANDIDATE_BY_ACCEPTED_HINT | RESOLVED_CANDIDATE_BY_ACCEPTED_HINT |
| customs.js + NO answer               | CANDIDATE_OPEN (eligible, unresolved)       | CANDIDATE_OPEN |
| fixture (clip/wrap, import-resolved) | unchanged, identity via resolver not TRACE  | RESOLVED_CANDIDATE_BY_ACCEPTED_HINT, resolver identity |
| emails.js (property BROKEN)          | unchanged REJECTED                          | REJECTED_FALSE_POSITIVE |
| ambiguous bucket C / no-body D       | remain UNKNOWN (no identity)                | denied (unique=false / no entry) |
| property outcomes (ESTABLISHED/BROKEN)| unchanged (property producer untouched)    | unchanged |

Only the customs.js disposition moves, and only when a semantic answer is present. The trace
mechanism makes the transform ELIGIBLE for hint acceptance; it never resolves a candidate by
itself, and the deterministic layer stays SEMANTICALLY_OPEN (identity is not a semantic fact).

## What did NOT change
- The property-propagation layer, its lattice, and the frozen structural producers: untouched.
- The acceptance guard logic: untouched (only its subject_transform input can now be trace-backed).
- The paired customs experiment packets and oracle: frozen, unchanged.
- emails.js rejection and all ESTABLISHED/BROKEN property outcomes: unchanged.

## Thesis framing
Resolver coverage is systematically weak for member calls (0/565 in customs.js, 11/536 in
fxa-shared), but measured downstream impact in the present labeled candidate set is a single
candidate. The bridge is a constrained second identity proof — trace-verified, exact-body,
unique-callee only — not a relaxation of identity.
