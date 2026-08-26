# Identity-safe definition resolver (separately gated producer)

Resolves: path-member call -> fact-established semantic identity -> module/export identity
-> UNIQUE definition node -> body. ESTABLISHED only when the chain yields exactly one
definition; any ambiguity/unavailability -> UNKNOWN. NEVER repository name-search: the
module is resolved FIRST (from the import spec), then the export member is matched WITHIN
that uniquely resolved module, with a uniqueness check. Source text is attached only AFTER
identity resolution and never participates in selecting the definition.

Producer: export_definition_resolver.sc
Output (definition_resolution.tsv): call_node_id, semantic_identity,
definition_status(ESTABLISHED|UNKNOWN), definition_node_id, definition_file,
definition_line, definition_provenance, definition_body.

Did NOT change: source/propagation facts, path-scoped transform identity, evidence schema,
hint/promotion rules, adjudicator rules, disposition. The renderer now populates the
EXISTING definition_status field + body ONLY from this resolver's ESTABLISHED rows
(replacing the earlier naive spec_to_file name-lookup). Dispositions verified unchanged
(fixture RESOLVED_CANDIDATE_BY_ACCEPTED_HINT; corpus A/B CANDIDATE_OPEN).

Negative controls (all abstain or resolve correctly):
- duplicate function names in different modules -> resolves to the imported module only;
- local function shadowing an imported name    -> UNKNOWN;
- import alias {member: local}                  -> resolves member;
- external module not in tree                    -> UNKNOWN (source unavailable);
- object-member/method + dynamic dispatch        -> no import identity, not a candidate;
- multiple candidate definitions                 -> UNKNOWN (never picks one);
- workspace package (fxa-shared) unique export   -> ESTABLISHED via module-scope uniqueness.

## Ablation now instantiated (real FxA)
Condition A  sanitizePayload  path ESTABLISHED, callee ESTABLISHED, semantic identity
             UNKNOWN, definition UNKNOWN, body UNAVAILABLE (method, not an import).
Condition B  normalizeEmail   path ESTABLISHED, callee ESTABLISHED, semantic identity
             ESTABLISHED (fxa-shared#normalizeEmail), definition ESTABLISHED
             (fxa-shared/email/helpers.ts:8), body AVAILABLE (return toLowerCase()).
The two differ ONLY in evidence availability -> the ablation the experiment needs.

## Experiment layout (strict isolation)
blind/   conditionA/llm_input.json, conditionB/llm_input.json, run_blind.py
         run_blind.py reads ONLY blind/, makes the real model request directly, writes
         raw_response.json + parsed_semantic_hint.json; never reads oracle/; never changes
         deterministic_status; never feeds the hint back into adjudication.
oracle/  conditionA_known_answer.json, conditionB_known_answer.json, source_evidence/,
         compare.py (run AFTER the blind call; reads blind outputs + oracle labels).
Ground truth (both UNSAFE from source) is NOT present in any blind payload (verified;
Condition B's body legitimately contains toLowerCase as evidence, which is the point).

Still operational-only: supply ANTHROPIC_API_KEY to run_blind.py to execute the blind call.
