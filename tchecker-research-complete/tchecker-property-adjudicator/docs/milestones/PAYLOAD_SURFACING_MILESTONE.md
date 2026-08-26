# Corpus payload surfacing fix (renderer / evidence-completeness milestone)

Renderer-only. No upstream facts, adjudication rules, hint-acceptance rules, or candidate
disposition moved (verified: path-scoped facts md5 stable; corpus disposition CANDIDATE_OPEN
before and after; fixture disposition RESOLVED_CANDIDATE_BY_ACCEPTED_HINT before and after).

## 1. callee_name preserved independently of semantic identity
Every on-path transform now exposes call_node_id, path_order, callee_name (ESTABLISHED
call fact), semantic_identity + semantic_identity_status. Unknown module/member identity
renders as callee_name="sanitizePayload", semantic_identity=null,
semantic_identity_status="UNKNOWN". The question now names the operation:
  "Does the on-path call `sanitizePayload` at path position 0 (semantic identity UNKNOWN)
   bound the serialized size of the value, or can attacker influence remain effectively
   unbounded?"

## 2. Definition body only when the definition relation is established
definition_status is emitted per transform. Body is included ONLY when a semantic identity
is established AND uniquely resolves a definition file via the module identity (never by
repository name-search). For the corpus candidate (identity UNKNOWN) definition_status=UNKNOWN,
relevant_code = callsite only, with an explicit note that the body was not statically
resolved. No body is fabricated. A general repository-level definition resolver (handling
duplicate names, aliases, shadowing, shared method names, barrels, dynamic dispatch) is a
SEPARATE gated milestone; the current within-established-module lookup covers only uniquely
resolved single-definition modules (e.g. the controlled fixture's clip/wrap).

## 3. finding_id from production facts
Was the hard-coded fixture id. Now: serialize-dos:<repo/file>#sink<node>, e.g.
  serialize-dos:fxa/packages/fxa-auth-server/lib/customs.js#sink30064771145

## 4. Repeated transform occurrences kept distinct
The two on-path sanitizePayload calls retain their separate call_node ids
(order 0 @ 30064771223, order 1 @ 30064771209); not collapsed by matching display name.

## Result
The FxA payload now names the operation under review (sanitizePayload), states exactly what
is and isn't statically known (path_membership ESTABLISHED vs semantic_identity UNKNOWN vs
definition_status UNKNOWN), and does not fabricate a body. That is the fair input for the
live-model experiment, and yields a clean ablation: on-path call identified + body
unavailable (customs.js sanitizePayload) vs on-path call + resolved body (emails.js
normalizeEmail, identity fxa-shared#normalizeEmail).
