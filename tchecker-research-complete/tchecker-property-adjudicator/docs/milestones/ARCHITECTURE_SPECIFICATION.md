# TChecker JS/TS Evidence Architecture — Architectural Specification

Status: consolidation of the validated system. This document specifies what the system
establishes, what it deliberately does not assert, the evidence/hint boundary, the frozen
production interfaces, the evaluation methodology, and the known limits. It adds no scope.

Scope of validation. Two things were validated and are distinguished throughout:
(a) the CanonicalEvidenceSet **interface**, stress-tested across five distinct
security-mechanism shapes with per-class gates and a perfect-diagonal cross-class
contamination matrix; and (b) the **end-to-end production adjudicator** for the
serialize-DoS sink class (source → propagation → path-scoped transform identity →
identity-safe definition resolution → CanonicalEvidenceSet → LLM payload), validated on a
controlled fixture and replayed unchanged on real FxA corpus candidates. The live-model
evaluation harness is built and frozen but has not been executed.

---

## 1. Deterministic guarantees (what the system establishes)

All of the following are established from the analyzer's own CPG/dataflow facts and carry
stable CPG node identities. Code text is display material only; it never participates in
establishing any of these.

1.1 Source→sink path membership. For a gated sink (JSON.stringify argument), the existence
of a data-dependence flow from a request-shaped source (`req.(body|payload|query|params)`)
is established by the analyzer's own dataflow engine (`reachableByFlows`, DDG), not by
string matching. Each established origin is a distinct alternative with its own stable
source node id.

1.2 Ordered transform membership on a path. A call is a transform for an origin alternative
only if its stable CPG call-node identity lies ON that alternative's established
source→sink flow. Membership and order are taken from the propagation relation
(path-scoped), never from "what is data-dependent on the source." Repeated occurrences of
the same callee are preserved as distinct path elements by node id.

1.3 Callee name. The syntactic callee name at a call node is an established fact,
independent of semantic identity.

1.4 Semantic identity (module#member) where uniquely determinable. Resolved through the
existing import/module/export identity facts (R23b import bindings, R14 module/export).
Established only where the chain is unambiguous; otherwise UNKNOWN.

1.5 Unique definition resolution where the identity chain is unambiguous. Given an
established semantic identity, the definition resolver returns exactly one definition node
(file, line, node id) only when the module resolves uniquely and the export member resolves
to exactly one definition within it. Body text is attached only after this resolution and
never participates in selecting the definition.

1.6 Qualification. Established dataflow is qualified `may; not proven necessary` — never
promoted to `must`.

---

## 2. Explicit non-assertions (what the system deliberately does not claim)

2.1 Semantic behavior of unresolved operations. If semantic identity or the definition is
UNKNOWN, the system does not assert what the operation does. It records callee name and
path membership and leaves the semantic property UNKNOWN.

2.2 Anything requiring name-based guessing. The definition resolver never selects a
definition by searching the repository for a matching function name. Module identity is
resolved first; the export is matched within the uniquely resolved module with a uniqueness
check; ambiguity yields UNKNOWN.

2.3 Necessity. The system asserts reachability (`may`), not that the flow is necessary
(`must`).

2.4 Promotion of a hint to a fact. A semantic hint from a model is never treated as an
established fact absent an explicit acceptance rule (Section 3). A hint never mutates any
deterministic status.

2.5 Cross-shape inference. Fields belonging to other security-mechanism shapes are marked
NOT_APPLICABLE with a reason, not silently defaulted.

---

## 3. Evidence/hint separation and adjudication_use semantics

Three axes are kept strictly separate:

- `deterministic_status`  — what static analysis establishes about a semantic property.
  For properties requiring semantic judgement it is UNKNOWN and STAYS UNKNOWN. A hint never
  changes it.
- `semantic_hint`         — `{proposed_value ∈ {SAFE,UNSAFE,UNKNOWN}, confidence, source="LLM"}`.
  Advisory. Recorded separately; carried into later prompts as
  PRIOR_SEMANTIC_HINTS_ADVISORY, never as fact.
- `adjudication_use`      — how TChecker USES a hint: `ACCEPTED_HINT | REJECTED_HINT |
  NEEDS_MORE_REVIEW`. Set by an explicit acceptance rule. Using an accepted hint to reach a
  disposition does not rewrite the underlying property as established.

Thesis statement. Static analysis establishes facts; semantic review supplies advisory
interpretations; TChecker may use accepted interpretations in adjudication while preserving
that the underlying property was not deterministically established. The deterministic
coverage of a finding therefore remains SEMANTICALLY_OPEN even when a disposition is reached
via accepted hints (e.g. RESOLVED_CANDIDATE_BY_ACCEPTED_HINT).

Iterative Semantic Hinting. Evidence set = state of knowledge. Each round emits one focused
LLM input for one still-unresolved property; a returned hint is folded into a separate
field and (if an acceptance rule fires) marked ACCEPTED_HINT; the loop continues only for
properties that remain unresolved. Per-alternative closure: a candidate clears only when the
required property is resolved for EVERY established alternative.

---

## 4. Frozen production interfaces

Producers (facts; do not modify semantics):
- `export_sourcefact.sc`         — SourceFact: per-origin provenance, stable node ids,
  STATIC_PROVENANCE vs LEXICAL_HINT (hints never promoted).
- `export_propagation.sc`        — dataflow-established source→sink relation, ordered path
  call nodes, `may` qualification, abstention when no flow.
- `path_transform_identity.py`   — path-scoped transform membership + identity via import
  facts; UNKNOWN when not an import binding.
- `export_definition_resolver.sc`— identity-safe definition resolution (module→export→unique
  definition); UNKNOWN on any ambiguity/unavailability; body attached only after resolution.
- R-series identity facts: `import_bindings.sc` (R23b), `module_export_identity.sc` (R14).

Adjudicator / renderer:
- `adjudicate_js.py`             — CanonicalEvidenceSet construction, Iterative Semantic
  Hinting loop, hint/acceptance handling, LLM-input rendering. Rules, hint model, and
  disposition are frozen; only rendering consumes new evidence-completeness facts.

Schema (CanonicalEvidenceSet / LLM input):
- Evidence sections: ESTABLISHED_BY_STATIC_ANALYSIS, SEMANTICALLY_UNRESOLVED,
  NOT_APPLICABLE, RELEVANT_CODE, plus `source_to_sink_paths` (first-class, fact-consumed).
- LLM-input sections: STATICALLY_ESTABLISHED, SOURCE_TO_SINK_PATHS,
  PRIOR_SEMANTIC_HINTS_ADVISORY, STILL_NOT_DETERMINISTICALLY_ESTABLISHED, RELEVANT_CODE,
  QUESTION, answer_contract. Per-step and per-subject: callee_name_status,
  semantic_identity_status, definition_status, body_supplied kept independent.

Interface stress-test (validates the interface, not new end-to-end scope): the same
CanonicalEvidenceSet carried five distinct shapes — data-dependence (serialize-DoS),
control-flow protection (guard-fallthrough), iteration/validation effect (validation-bypass),
predicate/domain mismatch (denylist-bypass), shared-state/aliasing (global-mutation) — each
with its own gate and a strictly diagonal cross-class contamination matrix and zero
fabricated facts. Only the serialize-DoS class is exercised end-to-end through the
adjudicator and live-model harness.

---

## 5. Evaluation methodology and integrity controls

5.1 Blind harness. `blind/run_blind.py` reads only its own payloads, sends the exact
production `llm_input.json` to the model, parses the reply into a
`SemanticHint {subject_node_id, property, proposed_value, confidence, rationale, source="LLM"}`,
and writes it alongside the payload. It never reads the oracle, never changes
`deterministic_status`, and never feeds the hint back into adjudication. With no API key it
writes PENDING and fabricates nothing.

5.2 Oracle isolation. Hidden ground truth and source evidence live under `oracle/`, physically
separate. `oracle/compare.py` runs only after the blind call. Ground truth is never present in
any blind payload (verified).

5.3 Two experiments (not one matched pair).
- Experiment 1 — evidence-boundary calibration (customs.js/sanitizePayload): identity and
  definition UNKNOWN, body unavailable. Tests calibrated abstention.
- Experiment 2 — body-context ablation (emails.js/normalizeEmail): the same candidate held
  fixed, varying only whether the identity-safe resolved body is supplied (B0 withheld / B1
  supplied). Byte-identical except the body field and its wording; both frozen and hashed
  before any live call.

5.4 Separate scoring axes.
- `oracle_correctness`          — proposed_value vs the hidden full-source truth.
- `evidence_grounded_correctness` — proposed_value vs the behavior justified by the SUPPLIED
  evidence (e.g. UNKNOWN when the body is absent). These may diverge by design; the
  divergence is itself a measurement.
- Experiment 2 additionally reports the causal effect: did supplying the body move B1
  relative to B0, toward the oracle truth?

---

## 6. Known limitations and unproven areas

6.1 No live-model results. The harness is frozen but unexecuted; no API credential was
available in the build environment. All model-behavior claims are hypotheses until run.

6.2 Definition-resolver coverage is not exhaustive. Validated abstention/resolution on:
duplicate names across modules, local shadowing, import alias, external-unavailable,
method/dynamic-dispatch (no import identity), multiple-candidates→UNKNOWN, and a workspace
package with a unique export (fxa-shared#normalizeEmail). NOT exhaustively tested:
re-export/barrel chains of depth >1, default vs named export disambiguation, and shared
object-method names under a known receiver type. These currently fall to UNKNOWN when
ambiguous, which is safe, but their resolution is not proven.

6.3 Single corpus. Corpus replay used mozilla/fxa only (convict, nunjucks, send had no
surviving serialize candidate). Transfer to other real corpora is unproven.

6.4 Single sink class end-to-end. Only serialize-DoS (JSON.stringify) is exercised through
the full adjudicator and harness. The other four shapes validate the interface, not the
end-to-end production path.

6.5 Provisional source endpoint. The propagation source seed is request-shaped; the
SourceFact hierarchy is the authoritative provenance. The relation being productionized
(path + identity + resolution) is dataflow-based regardless, but the endpoint choice is
provisional.

6.6 Necessity not modeled. Only `may` reachability is established; `must` necessity is out
of scope.

---

## 7. Suggested next validation

Run the two already-frozen experiments against a real model, unchanged: supply an API
credential to each `blind/run_blind.py`, execute, then run `oracle/compare.py`. Report
oracle_correctness and evidence_grounded_correctness separately, and the B1-vs-B0 causal
effect. No producer, schema, adjudication rule, hint rule, or payload should change for this
run; the payloads are hashed and frozen. This measures whether the explicit representation
of knowns and unknowns keeps the model reasoning within the evidence boundary — the claim
the architecture is built to support — without any further expansion of scope.
