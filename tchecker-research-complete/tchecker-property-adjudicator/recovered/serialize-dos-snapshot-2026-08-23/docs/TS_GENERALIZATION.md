# TypeScript held-out generalization test (frozen pipeline, no tuning)

Target shape (the branch node-http-proxy did NOT exercise):
    request-derived input -> user-defined MEMBER-METHOD transform -> serialization sink

Repo (unseen, not used in development): novuhq/novu (TypeScript backend).
File: apps/api/src/app/shared/framework/idempotency.interceptor.ts
Flow: request.body -> this.hashRequestBody(request.body) -> bodyHash -> {status, bodyHash}
      -> JSON.stringify(val)         (hashRequestBody = createHash('blake2s256')...digest('hex'))

## Results (frozen pipeline, TS CPG via jssrc2cpg)
| candidate | property outcome | disposition | correct? |
|---|---|---|---|
| INNER: JSON.stringify(body) inside hashRequestBody | ESTABLISHED | RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS | yes — the full request.body is serialized to feed the hash; attacker controls size at that sink |
| OUTER: JSON.stringify(val) after the hash          | BROKEN      | REJECTED_FALSE_POSITIVE | verdict yes (bodyHash is a fixed-length hash, so val's size is not attacker-controlled) — but see the path finding |

Trace-backed identity on TS: `this.hashRequestBody` -> UNIQUE
(idempotency.interceptor.ts::program:IdempotencyInterceptor:hashRequestBody). The member-method
transform is trace-identified exactly as customs.js `sanitizePayload` was — trace identity
GENERALIZES to out-of-corpus TypeScript.

## What generalized (positive)
- Property propagation: ESTABLISHED (inner) and BROKEN (outer) are both plausible, correct verdicts
  on brand-new TS code.
- Trace-backed identity: a `this.`-member-method transform is correctly and uniquely identified.
- Step 6 disposition: the inner ESTABLISHED candidate maps to RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS
  and carries the property_vs_vulnerability residual note. The disposition fix generalizes.

## Finding (documented, not fixed — frozen protocol)
The OUTER candidate SHOULD have reached OPEN: `hashRequestBody` is a user-defined transform whose
size effect is unknown to structure alone (seq10: VALUE_TRANSFORM / UNKNOWN). A clean analysis would
be OPEN -> semantic review -> SAFE (a hash bounds size), USING the trace-identified callee.
Instead reachableByFlows enumerated a single, TANGENTIAL path that leaves the hash chain and stitches
`bodyHash -> err` (seq13, a cross-variable over-approximation) into `buildError`, breaking at a
comparison `error.status || error.response?.statusCode` (seq16, CONTROL_DEPENDENCE -> BREAKS).

Consequences:
- The verdict is coincidentally CORRECT here (reject): the outer sink is genuinely not
  attacker-size-controlled, so BROKEN and the ideal OPEN->SAFE both reject.
- But the intended OPEN + semantic-review + trace-identity-CONSUMPTION path was pre-empted. Trace
  identity was COMPUTED (hashRequestBody UNIQUE) yet not CONSUMED, because no OPEN candidate
  materialized on this flow.
- Risk class: when reachableByFlows enumerates ONLY a spuriously-broken path (missing the
  legitimate one), the candidate outcome is decided by the spurious break. Here it is benign; in
  general it could cause a FALSE NEGATIVE (rejecting a real candidate). This is a reachableByFlows
  path-ENUMERATION limitation, not a property-layer classification defect — the comparison-break
  rule fired correctly, just on a spurious edge.

## Net
Trace-backed identity, property propagation, and the Step 6 disposition all generalize to an unseen
TypeScript backend. The OPEN + trace-identity-consumption branch was NOT cleanly exercised here,
because the one real member-method candidate short-circuited to BROKEN via a spurious flow
enumeration. That branch remains to be exercised on out-of-corpus code, and the spurious-path
enumeration is the concrete new-code finding this test produced.
