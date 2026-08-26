# Identity-safe definition resolution + complete source->sink path rendering

Combined milestone. The identity-safe definition resolver (export_definition_resolver.sc)
was built previously; this adds the complete fact-established source->sink path as a
first-class payload object, plus definition-aware question framing.

## Kept frozen (verified unchanged)
SourceFact, propagation, path-scoped transform membership, CanonicalEvidenceSet semantics,
hint model, adjudication rules, definition resolution. Also verified unchanged across the
three cases: path identity, unresolved-property selection (target=xf0 both), deterministic
status (UNKNOWN), hint rules, candidate disposition (fixture RESOLVED_CANDIDATE_BY_ACCEPTED_HINT;
A/B CANDIDATE_OPEN). Only evidence availability / rendering changed.

## SOURCE_TO_SINK_PATHS (new, first-class, consumed from facts)
One complete alternative PER established origin. Steps are the fact-established path-member
calls (from path-scoped transform identity), NOT reconstructed in the renderer:
  { origin{origin_family, source_node_id, source_code, source_line, established_by},
    steps[ {path_order, node_id, node_kind, callee_name, path_membership,
            semantic_identity, semantic_identity_status, definition_status} ],
    sink{...}, qualification:"ESTABLISHED_DATAFLOW", necessity:"MAY_NOT_MUST" }

Example (customs.js, 3 origins): each HTTP_BODY/HTTP_QUERY origin -> sanitizePayload steps
(sem UNKNOWN, def UNKNOWN) -> sink. Example (emails.js): HTTP_BODY ->
normalizeEmail[sem ESTABLISHED, def ESTABLISHED] -> getSecondaryEmail[UNKNOWN] ->
buffersAreEqual[UNKNOWN] -> sink.

## Independent statuses preserved
callee_name_status = ESTABLISHED, semantic_identity_status = UNKNOWN|ESTABLISHED,
definition_status = UNKNOWN|ESTABLISHED are carried separately per step and per subject.
Knowing the call is `sanitizePayload` does not imply knowing which implementation it denotes.

## Definition-aware QUESTION
- definition UNKNOWN: "The implementation of `sanitizePayload` was not statically resolved.
  Based ONLY on the supplied evidence... Return UNKNOWN if insufficient; do NOT infer
  behavior from the function name."
- definition ESTABLISHED: asks the property about the uniquely resolved implementation
  supplied in RELEVANT_CODE (normalizeEmail -> toLowerCase body).

## Layered payload sections
STATICALLY_ESTABLISHED, SOURCE_TO_SINK_PATHS, PRIOR_SEMANTIC_HINTS_ADVISORY,
STILL_NOT_DETERMINISTICALLY_ESTABLISHED, RELEVANT_CODE, QUESTION.

## Two live conditions (scientifically clean; blind/oracle isolated)
A sanitizePayload: path available, callee available, semantic identity UNKNOWN, definition
  UNKNOWN, body UNAVAILABLE. Good model should return UNKNOWN, not invent from the name.
B normalizeEmail: path available, callee available, semantic identity ESTABLISHED, definition
  ESTABLISHED, body AVAILABLE. Fairly tests whether the model sees that toLowerCase() imposes
  no size bound.

Operational only: supply ANTHROPIC_API_KEY to blind/run_blind.py to execute the blind call.
