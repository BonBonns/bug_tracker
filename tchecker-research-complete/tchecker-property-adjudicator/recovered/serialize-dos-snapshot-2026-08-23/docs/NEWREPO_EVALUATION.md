# New-repo frozen evaluation — results

Protocol frozen before results (neweval/PROTOCOL.md): run the frozen pipeline on repos NOT used in
development; classify; DOCUMENT any new failure class rather than fix it.

## Repos scanned (none used in development)
express, morgan, body-parser, node-express-boilerplate, http-proxy-middleware, express-session,
sequelize, node-http-proxy.

## Finding 1 — the target pattern is scarce (precision generalizes)
The serialize-DoS pattern (req.(body|payload|query|params) -> JSON.stringify) does NOT appear in
framework/middleware code: those serialize their OWN abstractions (res.json's `value`, session
`sess`, morgan `format`), not request fields. Idiomatic apps serialize via res.json/res.send, so
direct `JSON.stringify(req.*)` is rare. Across 8 real repos exactly ONE direct candidate exists
(node-http-proxy examples). On all the non-matching code the pipeline correctly produced NO
candidates — no false positives from generalization. (Note: `JSON.stringify(req.headers)` sites
exist but headers is intentionally NOT in the frozen source set, so they are correctly not raised.)

## Finding 2 — the one real candidate exposed a disposition gap (NEW failure class)
node-http-proxy/examples/middleware/bodyDecoder-middleware.js:48
    bodyData = JSON.stringify(req.body);     // pure direct flow, NO transform on the path

Frozen pipeline result:
- property_outcome = ESTABLISHED   (CORRECT — attacker controls serialized size/structure; the
  property classification generalizes perfectly to a brand-new repo)
- unresolved transforms = 0
- disposition = RESOLVED_SAFE_BY_ACCEPTED_HINT   (WRONG)

Root cause (adjudicate, no code change made): with zero transforms `props` is empty, so
`not_adjudicable` and `unsafe` are both vacuously empty and the function falls through to
`RESOLVED_SAFE_BY_ACCEPTED_HINT`. Two defects in that outcome:
  1. "SAFE" is incorrect: an ESTABLISHED property with NO bounding transform means the attacker
     value is serialized unmodified -> a confirmed serialize-DoS, not safe.
  2. "BY_ACCEPTED_HINT" is a misnomer: no hint exists (no transform to review).

Why the corpus missed it: every motivating candidate had >=1 transform (customs.js sanitizePayload)
or was BROKEN (emails.js) or reached the adjudicator with a transform (123done sink -> 1 unresolved
-> CANDIDATE_OPEN). The pure-direct, zero-transform ESTABLISHED path was never exercised end-to-end.
The frozen evaluation surfaced it on the first out-of-corpus direct candidate.

## Scope of the generalization
- Property-propagation LAYER generalizes: NO_FLOW/BROKEN/OPEN/ESTABLISHED classification is correct
  on new code (direct flow -> ESTABLISHED).
- Trace-backed identity: not exercised here (direct flow has no transform); untested on this repo.
- Adjudicator DISPOSITION mapping does NOT generalize for the zero-transform ESTABLISHED case.

## Recommendation (for a FUTURE change; NOT applied in this frozen evaluation)
Disposition should distinguish:
  - ESTABLISHED property with no unresolved/unsafe transform on the path -> CONFIRMED CANDIDATE
    (attacker controls serialized size unmodified), NOT RESOLVED_SAFE.
  - "all transforms adjudicated and none UNSAFE" -> SAFE (the existing intent), which is only
    correct when there WAS at least one transform that was shown to bound/destroy the property.
The empty-props case must not be treated as vacuously safe. This is a disposition-layer fix; the
property layer and identity layer are unaffected.

Per protocol this is recorded, not fixed. It is the higher-value output of the evaluation: the
classification generalized, and a real disposition gap was found on genuinely new code.
