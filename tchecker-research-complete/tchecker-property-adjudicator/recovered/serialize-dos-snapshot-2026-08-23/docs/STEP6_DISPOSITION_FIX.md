# Step 6 — disposition follows the property layer (fix for the new-repo evaluation finding)

## Finding (from the frozen new-repo evaluation)
A pure direct `JSON.stringify(req.body)` (node-http-proxy bodyDecoder) was classified ESTABLISHED
by the property layer (correct) but dispositioned RESOLVED_SAFE_BY_ACCEPTED_HINT (wrong).
Characterization showed the same root cause affects ALL ESTABLISHED candidates:
  - 0 transforms  -> `unsafe`/`not_adjudicable` vacuously empty -> falls through to SAFE.
  - off-path transform (e.g. a cache `.set()` counted by transform_identity but NOT on the
    property flow) -> a spurious unresolved property -> CANDIDATE_OPEN.
In every case the disposition was re-derived from the transform-property model instead of
following the property layer, which had already proven attacker control reaches the sink.

## Fix (disposition layer only)
adjudicate() now returns, immediately after the BROKEN/NO_FLOW rejections and coverage
computation:
    value_preservation == "ESTABLISHED"  ->  RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS
This is a CONFIRMED candidate: the deterministic property layer established that attacker control
of serialized size/structure reaches the sink with no bounding transform. It is distinct from
OPEN (which still routes to semantic review) and is not a hint-based resolution. The evidence's
existing humility qualifier — ESTABLISHED_DATAFLOW(may; not proven necessary) — still applies;
this is a strong candidate per the modeled property, not a proven exploit.

## Strict regression (Step 6)
| case | expected | observed |
|---|---|---|
| bodyDecoder (ESTABLISHED, 0 xform)   | move -> RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS | ✓ |
| 123done / post-nimbus / oauth (ESTABLISHED) | move -> RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS | ✓ |
| customs.js OPEN + answer             | unchanged RESOLVED_CANDIDATE_BY_ACCEPTED_HINT | ✓ |
| customs.js OPEN + no answer          | unchanged CANDIDATE_OPEN | ✓ |
| fixture                              | unchanged RESOLVED_CANDIDATE_BY_ACCEPTED_HINT | ✓ |
| emails.js                            | unchanged REJECTED_FALSE_POSITIVE | ✓ |
| amb (ambiguous)                      | unchanged CANDIDATE_OPEN | ✓ |
| uni (unique)                         | unchanged RESOLVED_CANDIDATE_BY_ACCEPTED_HINT | ✓ |

Only ESTABLISHED candidates move. OPEN / BROKEN / NO_FLOW dispositions are untouched.

## What did NOT change
Property-propagation layer and lattice; trace-backed identity; the acceptance guard; the property
outcomes themselves; the paired customs experiment and its oracle; emails.js rejection. This is a
disposition-mapping correction that makes the adjudicator consistent with the frozen property
layer — no new classification, no relaxation of any gate.

## Terminology safeguard (added)
Evidence for an ESTABLISHED candidate now carries `property_vs_vulnerability`:
  {"established": "modeled security property only (not a confirmed DoS)",
   "residual_vulnerability_questions": [effective request-size bounds, reachability, repeatability,
                                        actual resource impact]}
OPEN/BROKEN/NO_FLOW candidates carry None. RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS therefore means
the modeled property is established, NOT that a DoS is confirmed. Disposition logic unchanged.
