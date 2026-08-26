# Polymorphism control for Step 4 (negative + positive), then freeze

Safety claim under test: trace-backed identity is accepted ONLY when the call maps to exactly one
callee body. The dangerous failure mode is accidentally promoting an ambiguous call.

## Fixtures (same shape; only the receiver differs)
- amb: `const obj = flag ? new A() : new B(); obj.transform(req.body)` — one call site, two bodies.
- uni: `const obj = new A(); obj.transform(req.body)` — receiver constrained to one body.

## What jssrc2cpg does (and why the ambiguity signal is the call graph, not the trace)
For the ambiguous receiver, jssrc2cpg emits the call with `methodFullName = "A | B:transform"` and
`dispatchType = DYNAMIC_DISPATCH` (a synthetic union method). Critically, reachableByFlows may
enumerate only ONE polymorphic target — so counting entered bodies alone is not safe. The producer
therefore denies identity on ANY CPG-visible ambiguity signal:
  - union methodFullName (" | "), OR
  - call.callee resolving to more than one distinct local (non-external) method, OR
  - more than one distinct callee body actually entered.
This closes the under-enumeration gap: an ambiguous call cannot be promoted even if the trace
happened to walk into a single target.

## Results — three checks, run separately
| check | amb (ambiguous) | uni (unique) |
|---|---|---|
| 1. identity producer      | DENIED AMBIGUOUS(A \| B:transform), unique=false | UNIQUE A:transform, unique=true |
| 2. adjudicator identity   | subject_transform = UNKNOWN | subject_transform = TRACE-established |
| 3. end-to-end (same HIGH-confidence answer) | NEEDS_MORE_REVIEW -> **CANDIDATE_OPEN** | ACCEPTED_HINT -> RESOLVED_CANDIDATE_BY_ACCEPTED_HINT |

Check 3 is the decisive one: an identical plausible HIGH-confidence semantic answer resolves the
unique call but CANNOT resolve the ambiguous call. Ambiguity blocks promotion downstream, not just
in the producer's label.

## Full regression (unchanged by the hardening)
    customs.js + answer     -> RESOLVED_CANDIDATE_BY_ACCEPTED_HINT   (sanitizePayload still unique)
    customs.js + NO answer  -> CANDIDATE_OPEN
    fixture                 -> RESOLVED_CANDIDATE_BY_ACCEPTED_HINT   (identity via resolver, not TRACE)
    emails.js               -> REJECTED_FALSE_POSITIVE
    amb                     -> CANDIDATE_OPEN
    uni                     -> RESOLVED_CANDIDATE_BY_ACCEPTED_HINT

## Freeze
Step 4 (trace-backed exact-callee identity) is frozen with this control in place. The mechanism
establishes identity only for a unique, non-ambiguous, trace-entered callee whose exact body is
supplied to adjudication; ambiguous and bodiless calls remain UNKNOWN and cannot be promoted even
with a high-confidence semantic answer. No further identity tests planned unless a new-repo
evaluation exposes another failure class.
