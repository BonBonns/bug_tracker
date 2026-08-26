# PATH_CODE_CONTEXT milestone

Attaches actual code to the already-established source->sink path, keyed by NODE ID only
(never by name search). Three layers kept separate in the payload:
  SOURCE_TO_SINK_PATHS  = ordered graph/path facts
  PATH_CODE_CONTEXT     = actual code on established path nodes
  SEMANTIC_EVIDENCE     = STATICALLY_ESTABLISHED + STILL_NOT_DETERMINISTICALLY_ESTABLISHED
                          (established properties + explicit UNKNOWNs)

New producer: export_path_code_context.sc — for each node id the fact layer already
established (source, path-step call nodes, sink), extracts exact code, containing statement,
and containing function from the CPG by id. Definition bodies are NOT produced here; they
come from the frozen definition resolver and are included per step only when
definition_status = ESTABLISHED. UNKNOWN steps show the callsite; the body is never invented.

Renderer: consumes path_code_context.tsv (+ the resolver output) to emit PATH_CODE_CONTEXT
as a first-class layer, one entry per path alternative:
  SOURCE { node_id, expression, containing_statement, containing_function }
  STEP N { call_node_id, callsite_code, containing_statement, containing_function,
           callee_name, definition_status, definition_body(if ESTABLISHED else null) }
  SINK   { node_id, expression, containing_statement, containing_function }

Not changed (verified): source detection, propagation, transform identity, definition
resolution, hint logic, adjudication rules. Disposition invariant (fixture
RESOLVED_CANDIDATE_BY_ACCEPTED_HINT; A/B CANDIDATE_OPEN); unresolved-property selection and
deterministic_status unchanged.

Ablation integrity: B0 withholds the resolved body EVERYWHERE (RELEVANT_CODE and
PATH_CODE_CONTEXT); verified 0 occurrences of the body in B0, present in B1. Re-frozen:
  B0 sha256 ee6fcf22...   B1 sha256 4bc54a31...

FxA candidate now renders (B1):
  SOURCE  request.payload (handler)
  STEP0   normalizeEmail(email)  -> def: return originalEmail.toLowerCase()
  STEP1   db.getSecondaryEmail(normalizedEmail)  -> def UNKNOWN
  STEP2   butil.buffersAreEqual(existingRecord.uid, uid) -> def UNKNOWN
  SINK    JSON.stringify({ uid: uidStr, secret })
The model can inspect the actual code on the established path while path facts, code
context, semantic facts, and unresolved semantics stay separate.
