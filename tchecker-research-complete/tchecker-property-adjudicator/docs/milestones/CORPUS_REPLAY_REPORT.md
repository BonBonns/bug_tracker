# Independent real-corpus replay — frozen serialize pipeline + unchanged adjudicator

Boundary preserved: controlled fixture validates architecture mechanics; this run tests
whether the FROZEN mechanics transfer, unchanged, to independently authored JS/TS.

Nothing modified: serialize detector semantics, source/sink definitions, propagation
producer, transform-identity producer, CanonicalEvidenceSet, hint/promotion rules,
adjudicator RULES. Only the adjudicator's I/O was de-fixtured (env-configurable input
dir + target sink; origin display coordinates read from the propagation fact layer).
The fixture run is byte-identical after this I/O change.

## Corpus
mozilla/fxa @ e1a8c43 (2026-08-21); also scanned node-convict@ba7693f, nunjucks@2025c93,
send@ade10e4. Frozen serialize pipeline (sinks = JSON.stringify args; sources =
req.(body|query|params); relation = reachableByFlows DDG).

## Surviving SEMANTICALLY_OPEN candidates: 6 (all in fxa)
1. fxa-auth-server/lib/customs.js            sink node 30064771145 L75  JSON.stringify(requestData)   origins HTTP_BODY,HTTP_QUERY
2. fxa-auth-server/lib/routes/emails.js      sink node 30064771763 L612 JSON.stringify({uid,secret})  origin HTTP_BODY
3. fxa-auth-server/lib/routes/emails.js      sink node 30064771931 L227 JSON.stringify({uid,secret})  origin HTTP_BODY
4. fxa-content-server/.../post-nimbus-experiments.js sink 30064773965 L28  origins HTTP_BODY (direct, no transform)
5. fxa/packages/123done/server.js            sink node 30064774395 L215 JSON.stringify(req.body)       origin HTTP_BODY (direct)
6. fxa/packages/123done/oauth.js             sink node 30064774802 L302 origins HTTP_QUERY (direct)

Ordered transform identities are fact-backed (import-binding join). On this corpus most
resolve UNKNOWN (local/method callees, not import bindings); `normalizeEmail` resolves to
`fxa-shared#normalizeEmail` (ESTABLISHED) on the emails.js paths. UNKNOWN identities are
kept UNKNOWN (abstention) — never repaired by source-reading. Fabricated associations: 0.

## Selected: candidate #1 (customs.js, sink 30064771145) — first established
Ran the UNCHANGED adjudicator rules. Artifacts in cand1-out/:
  evidence_v0.json   origin HTTP_BODY(node 225) STATIC_PROVENANCE; transform chain of 5,
                     all identities UNKNOWN; 5 unresolved size-bounding properties;
                     origin display (request.payload@L130) from the propagation fact layer.
  llm_input_1.json   exact payload; STATICALLY_ESTABLISHED chain + the one targeted
                     unresolved property (subject_transform UNKNOWN); HINT answer contract.
  hint_1.json        controlled architecture-validation injection (LOW/UNKNOWN), NOT a live
                     model output.
  evidence_v1.json   hint folded; deterministic_status stays UNKNOWN; because the subject
                     identity is UNKNOWN the acceptance rule yields NEEDS_MORE_REVIEW.
  llm_input_2.json   next query emitted; replay halts here (no live model in step 2).
  adjudication_trace.json

Final: CANDIDATE_OPEN (deterministic layer SEMANTICALLY_OPEN). Correct conservative
behavior: with the transform identity unresolved, a low-confidence hint is not accepted
for adjudication and the candidate stays open pending review / a live-model hint.

## Findings surfaced by the replay (not present on the controlled fixture)
1. The frozen transform-identity producer (argument-dataflow attribution) OVER-ATTRIBUTES
   on real code: it lists every call the request value flows into, which is broader than
   the propagation producer's path-to-sink chain. The two frozen producers diverge on
   real code; the fixture masked this. (Reported, not silently repaired.)
2. Most real transform callees are local/method calls, so identity resolves UNKNOWN; the
   fact-backed join only establishes identity for import bindings (e.g. fxa-shared).
Both are honest limitations of the current frozen producers, to be addressed under a
separate gated milestone — not by widening the detector or reading source in the adjudicator.

## Result
The frozen mechanics transfer unchanged: an independently authored real candidate flows
from the frozen production pipeline into evidence_v0 and the exact llm_input payload; the
hint model and per-property closure behave conservatively where identity is unresolved;
zero fabricated associations. Live-model hint quality remains step 3.
