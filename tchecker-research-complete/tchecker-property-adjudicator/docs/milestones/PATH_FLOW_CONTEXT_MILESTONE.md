# PATH_FLOW_CONTEXT milestone

Exposes the fact-established transitions BETWEEN path nodes — the reachableByFlows dataflow
edges — so the LLM can see how the value actually moves through variables, arguments,
parameters, returns, fields, and assignments. No analysis semantics or adjudication logic
changed.

Four structural/code layers now, kept separate:
  SOURCE_TO_SINK_PATHS  graph identities/order
  PATH_CODE_CONTEXT     code at established nodes
  PATH_FLOW_CONTEXT     code/relations connecting the nodes   <-- new
Semantic evidence stays separate:
  STATICALLY_ESTABLISHED, STILL_NOT_DETERMINISTICALLY_ESTABLISHED

New producer: export_path_flow_context.sc. For each established (source, sink) pair it takes
the reachableByFlows dataflow path and emits every consecutive transition:
  from_node_id, to_node_id, relation_kind, from_expression, to_expression,
  containing_statement, containing_function.
relation_kind is classified from CPG node structure ONLY (ASSIGNMENT, ARGUMENT_TO_PARAMETER,
RETURN_TO_CALL, CALL_RESULT_TO_LOCAL, PROPERTY_READ, ALIAS, ...); UNKNOWN when the structure
does not establish it. No transition or relation is inferred from source text; nothing is
invented.

Renderer: consumes path_flow_context.tsv and emits PATH_FLOW_CONTEXT per path alternative,
collapsing intra-statement noise (keeps each transition that enters a new containing
statement or carries a non-UNKNOWN relation) so the sequence reads as the bridging code.

Validation (FxA emails.js, reading the packet ONLY):
  request.payload -> _tmp_212.email -> email -> normalizeEmail(email) -> normalizedEmail
  -> db.getSecondaryEmail(normalizedEmail) -> existingRecord -> existingRecord.uid -> uid
  -> const uidStr = ... String(uid) -> { uid: uidStr, secret } -> JSON.stringify(...)
A reader who has never seen the FxA repository can now follow why request.payload connects
to that JSON.stringify, using only the supplied evidence packet.

Not changed (verified): source detection, propagation, transform identity, definition
resolution, hint logic, adjudication rules. Disposition invariant (fixture
RESOLVED_CANDIDATE_BY_ACCEPTED_HINT; A/B CANDIDATE_OPEN); unresolved-property selection and
deterministic_status unchanged. Ablation integrity preserved: B0 withholds the resolved body
everywhere (0 occurrences) while B1 supplies it.
