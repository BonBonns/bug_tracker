# JS/TS adjudicator — fact-backed transform identity + Iterative Semantic Hinting

## Claim separation (per review)
CONTROLLED ARCHITECTURE PROOF (this artifact): a controlled JS/TS candidate processed by
the ACTUAL CPG (jssrc2cpg) and the production fact producers drives the complete iterative
adjudication state machine. `finding/report_handler.js` is a controlled fixture executed on
a real parser/CPG/dataflow — NOT a real-corpus finding.
STILL TO PROVE (next): the same frozen adjudicator, unchanged, on an independently authored
real-corpus JS/TS candidate. Then: whether a live model can produce accurate typed hints.

## Correction 1 — transform identity is fact-backed (the leak is closed)
Previously the adjudicator inferred which transform belonged to an origin by rereading
source. On the earlier two-origin fixture the dataflow engine actually establishes
`normalize` (node 106) on BOTH origins; `shape` is on NO established flow. The old
`altA -> shape` association was a SOURCE-DERIVED FABRICATION.

Now `export_transform_identity.sc` establishes, per origin, the ordered transform chain by
ARGUMENT DATA-DEPENDENCE (stable node identity) and resolves each transform's identity via
the R23b/R14 import bindings (module#member). The adjudicator CONSUMES
`transform_identity.tsv`; it never associates transforms by code text, name string,
source-line proximity, or source re-reading. RELEVANT_CODE only SHOWS code for a subject
already identified by facts.

Verification (required): with the finding source made unreadable, the fact-derived outputs
are byte-identical — evidence_v0 transform chain + unresolved subjects, round-1 target,
llm_input_1 STATICALLY_ESTABLISHED, and final disposition all unchanged; only RELEVANT_CODE
display text blanks. => association is 100% fact-backed.

Transform-identity report: established 2 (clip->./lib/clip#clip, wrap->./lib/wrap#wrap),
unresolved/abstained 0, FABRICATED ASSOCIATIONS 0.

## Correction 2 — LLM output is a HINT, not a resolution (Iterative Semantic Hinting)
Static analysis ESTABLISHES facts; the LLM PROPOSES a semantic interpretation; TChecker
decides acceptance. Folding a `SemanticHint {subject, property, proposed_value, confidence,
rationale, source=LLM}` sets a SEPARATE `semantic_hint` field and leaves
`deterministic_status = UNKNOWN`. A property is promoted to established_by=SEMANTIC_REVIEW
only when an EXPLICIT promotion rule fires (here: confidence=HIGH AND the subject transform
identity is fact-established). deterministic_status is never flipped by a hint.

Later prompts receive prior hints as PRIOR_SEMANTIC_HINTS_advisory (source=LLM, "advisory"),
kept distinct from STATICALLY_ESTABLISHED facts — "a prior semantic review suggested X;
reconsider the remaining uncertainty", never "this is now a fact".

## The finding (controlled fixture on real CPG)
`buildResponse(req)`: HTTP_BODY origin -> clip (order 0) -> wrap (order 1) -> JSON.stringify.
Dataflow establishes the ordered chain; each transform's size-bounding property is a
separate semantic unknown.

## State machine (adjudicate_js.py — orchestration only; detector semantics untouched)
Stage 0  evidence_v0.json      four-part split; transform chain + subjects consumed from facts;
                               per-transform bounding property deterministic_status=UNKNOWN.
Stage 1  llm_input_1.json      targets xf0 (clip) only; static facts + fact-identified subject
                               + code shown for it + narrow question; answer contract = HINT.
Stage 2  hint_1.json           SemanticHint(SAFE,HIGH) folded -> evidence_v1.json;
                               deterministic_status stays UNKNOWN; promotion rule accepts
                               (established_by=SEMANTIC_REVIEW).
Stage 3  llm_input_2.json      xf0 still deterministically UNKNOWN but accepted; xf1 (wrap)
                               remains -> second prompt carries the xf0 hint as advisory,
                               asks only about xf1, not a repeat.
         hint_2.json           SemanticHint(UNSAFE,HIGH) folded -> evidence_final.json.
         adjudication_trace.json  fact-state movement v0 -> v1 -> v2.

## Fact-state movement
    v0  CANDIDATE_OPEN                 xf0 UNKNOWN(no hint), xf1 UNKNOWN(no hint)
    v1  CANDIDATE_OPEN                 xf0 UNKNOWN + hint SAFE (accepted, SEMANTIC_REVIEW)
    v2  RESOLVED_CANDIDATE             xf1 UNKNOWN + hint UNSAFE (accepted) -> candidate stands
    (deterministic layer stays UNKNOWN throughout; disposition is review-informed)

## Invariants asserted by the driver
- transform association consumed from facts only (verified by the source-blanking test);
- deterministic_status stays UNKNOWN in every version (a hint never becomes a static fact);
- acceptance only via the explicit promotion rule, tagged SEMANTIC_REVIEW, never STATIC;
- the second prompt targets only the still-unresolved property, prior hint carried advisory.
