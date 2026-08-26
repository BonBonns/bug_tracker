#!/usr/bin/env python3
"""Production JS/TS adjudicator - Iterative Semantic Hinting.

Design corrections applied:
  1. TRANSFORM IDENTITY IS FACT-BACKED. The origin -> transform(s) -> sink relation and
     each transform's identity (module#member) are CONSUMED from transform_identity.tsv
     (produced upstream by argument-dataflow attribution + R-series import join). The
     adjudicator never associates a transform to an origin by code text, name string,
     source-line proximity, or source re-reading. RELEVANT_CODE only SHOWS code for a
     subject already identified by facts.
  2. LLM OUTPUT IS A HINT, NOT A RESOLUTION. Static analysis ESTABLISHES facts; the LLM
     PROPOSES a semantic interpretation; TChecker decides acceptance. Folding a hint sets
     a separate `semantic_hint` field and leaves `deterministic_status = UNKNOWN`. An
     explicit acceptance rule sets `adjudication_use` (ACCEPTED_HINT | REJECTED_HINT |
     NEEDS_MORE_REVIEW). TChecker may USE an accepted hint to reach an adjudication
     decision, but the underlying property is never rewritten as an established fact.
"""
import json
from pathlib import Path

import os
RAW = Path(os.environ.get("TCH_RAW", "find-out/raw"))
SRC = Path(os.environ.get("TCH_SRC", "finding"))
OUT = Path(os.environ.get("TCH_OUT", "adj-out")); OUT.mkdir(exist_ok=True)
TARGET_SINK = os.environ.get("TCH_SINK")          # pick a specific sink; default = first established
# Sink kind is RENDERING metadata, not a classifier input. Defaults to "JSON.stringify" for full
# backward compatibility with every fact table produced before framework sinks existed (none of
# them carry a sink-call-name fact). When a framework sink fired (e.g. API.v1.success), the caller
# supplies the observed call name via TCH_SINK_KIND so the packet doesn't misrepresent it as a
# literal JSON.stringify call.
SINK_CALL_KIND = os.environ.get("TCH_SINK_KIND", "JSON.stringify")

# PROPERTY CONFIG: the one seam between the generic engine (source->sink alternatives, ordered
# transforms, trace/static identity, OPEN/BROKEN/ESTABLISHED composition, multi-origin existential
# join, semantic-review scheduling, hint acceptance/abstention -- none of which is property-specific
# and NONE of which is touched by this config) and the vulnerability-shape-specific vocabulary
# (property name, property_id suffix, question wording, sink class/primitive, residual-vulnerability
# framing). Loaded from TCH_PROPERTY_CONFIG (a JSON file path) when set; otherwise defaults to the
# EXACT serialize-DoS config this file has always hardcoded, so every existing invocation without
# the env var set is byte-for-byte unchanged.
_DEFAULT_PROPERTY_CONFIG = {
    "property_name": "ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE",
    "property_id_suffix": "bounds_serialized_size",
    "vulnerability_class": "serialize-dos",
    "downstream_primitive": "JSON.stringify",
    "direct_sink_kinds": ["JSON.stringify", "EJSON.stringify"],
    "direct_sink_model": "DIRECT_SERIALIZATION",
    "indirect_sink_model": "FRAMEWORK_RESPONSE_SERIALIZATION",
    "focused_question_template": (
        "Does the on-path call `{callee_name}` at path position {order} "
        "(static definition identity {static_status}; trace callee identity {trace_status}) "
        "bound the serialized size of the value, or can attacker influence remain "
        "effectively unbounded?"),
    "established_meaning": "modeled security property only (not a confirmed DoS)",
    "residual_vulnerability_questions": [
        "effective request-size bounds (e.g. body-parser limits)",
        "reachability of the handler", "repeatability", "actual resource impact"],
}


def _load_property_config():
    path = os.environ.get("TCH_PROPERTY_CONFIG")
    if not path:
        return dict(_DEFAULT_PROPERTY_CONFIG)
    cfg = dict(_DEFAULT_PROPERTY_CONFIG)
    cfg.update(json.loads(Path(path).read_text()))
    missing = [k for k in _DEFAULT_PROPERTY_CONFIG if k not in cfg]
    if missing:
        raise ValueError(f"property config {path} missing required keys: {missing}")
    return cfg


PROPERTY_CONFIG = _load_property_config()
SINK_MODEL = (PROPERTY_CONFIG["direct_sink_model"] if SINK_CALL_KIND in PROPERTY_CONFIG["direct_sink_kinds"]
              else PROPERTY_CONFIG["indirect_sink_model"])


def sink_descriptor(node_id, line):
    """One sink dict used everywhere in the evidence/packet: distinguishes the call the analyzer
    actually identified (kind) from why it's security-relevant (sink_model) from what ultimately
    performs the write (downstream_primitive)."""
    d = {"node_id": node_id, "line": int(line), "kind": SINK_CALL_KIND, "sink_model": SINK_MODEL,
         "class": PROPERTY_CONFIG["vulnerability_class"],
         "downstream_primitive": PROPERTY_CONFIG["downstream_primitive"]}
    return d


def rows(name, n):
    p = RAW / name
    return [f for f in (ln.split("\t") for ln in (p.read_text().splitlines() if p.exists() else [])) if len(f) == n]


def line_of(relpath, lineno):
    t = (SRC / relpath).read_text().splitlines()
    return t[lineno - 1].strip() if 0 < lineno <= len(t) else ""


def spec_to_file(spec):
    return spec.lstrip("./") + ".js"


def func_src(relfile, name):
    p = SRC / relfile
    if not p.exists():
        return ""
    for l in p.read_text().splitlines():
        if f"function {name}" in l:
            return l.strip()
    return ""


def _build_alternative_evidence(alt_prefix, origin_id, chain, defres, trace_id, locked_res,
                                 def_by_node, transforms, unresolved, relevant):
    """Build transform/unresolved-property/relevant-code entries for ONE alternative (one origin's
    own on-path transform chain). Property ids are scoped by alt_prefix (e.g. 'o0.xf1...') so that
    multiple open alternatives on the same candidate never collide. Called ONLY for origins whose
    own property_outcome is OPEN -- BROKEN/NO_FLOW origins are already settled (no review needed,
    and showing their transforms would target the wrong evidence); ESTABLISHED origins resolve the
    candidate directly via Step 6, also without needing review."""
    for t in chain:
        order, call_node, callee, spec, member, status = t[2], t[3], t[4], t[5], t[6], t[7]
        callee_name = callee if callee else None
        callee_name_status = "ESTABLISHED" if callee_name else "UNKNOWN"
        semantic_identity = f"{spec}#{member}" if status == "ESTABLISHED" else None
        semantic_identity_status = status
        def_status, def_file, def_line, def_code = "UNKNOWN", None, None, None
        res = defres.get(call_node)
        tr = trace_id.get(call_node)
        locked = locked_res.get(call_node)
        if locked and locked["status"] == "ESTABLISHED":
            semantic_identity = locked["semantic_identity"]
            semantic_identity_status = "ESTABLISHED"
        trace_established = bool(tr and tr["unique"])
        if locked and locked["status"] == "ESTABLISHED":
            def_status = "ESTABLISHED_BY_LOCKED_DEPENDENCY"
            def_file, def_code = locked["files"], locked["body"]
            identity = "LOCKED:" + locked["semantic_identity"]
        elif res and res["status"] == "ESTABLISHED":
            def_status = "ESTABLISHED"
            def_file, def_line, def_code = res["file"], res["line"], res["body"]
            identity = semantic_identity if semantic_identity else "UNKNOWN"
        elif trace_established:
            def_status = "ESTABLISHED_BY_TRACE"
            def_code = tr["body"]
            identity = "TRACE:" + tr["callee_fullName"]
        else:
            identity = semantic_identity if semantic_identity else "UNKNOWN"
        def_by_node[call_node] = {
            "definition_status": def_status,
            "static_definition_identity": semantic_identity,
            "static_definition_identity_status": semantic_identity_status,
            "trace_callee_identity": (identity if identity.startswith("TRACE:") else None),
            "trace_callee_identity_status": ("ESTABLISHED" if def_status == "ESTABLISHED_BY_TRACE"
                                              else "NOT_ESTABLISHED"),
            "definition_body": def_code}
        if locked and locked["status"] == "ESTABLISHED":
            def_by_node[call_node]["locked_dependency_evidence"] = {
                "versions": locked["versions"], "integrities": locked["integrities"],
                "lockfile": locked["lockfile"], "definition_files": locked["files"],
                "provenance": locked["provenance"]}
        transforms.append({"order": int(order), "call_node": call_node, "alternative_origin": origin_id,
                           "callee_name": callee_name, "callee_name_status": callee_name_status,
                           "semantic_identity": semantic_identity,
                           "semantic_identity_status": semantic_identity_status,
                           "definition_status": def_status,
                           "established_by": "STATIC_PROVENANCE_IDENTITY_JOIN" if status == "ESTABLISHED" else None})
        prop_id = f"{alt_prefix}xf{order}.{PROPERTY_CONFIG['property_id_suffix']}"
        name_disp = callee_name if callee_name else "<callee-name-unresolved>"
        unresolved.append({
            "property_id": prop_id, "alternative_origin": origin_id,
            "subject_transform": identity, "subject_call_node": call_node,
            "callee_name": callee_name, "callee_name_status": callee_name_status,
            "semantic_identity": semantic_identity, "semantic_identity_status": semantic_identity_status,
            "definition_status": def_status,
            "deterministic_status": "UNKNOWN",
            "semantic_hint": None,
            "adjudication_use": None,
            "focused_question": PROPERTY_CONFIG["focused_question_template"].format(
                callee_name=name_disp, order=order, static_status=semantic_identity_status,
                trace_status=def_by_node[call_node]['trace_callee_identity_status'])})
        if def_status in ("ESTABLISHED", "ESTABLISHED_BY_TRACE", "ESTABLISHED_BY_LOCKED_DEPENDENCY"):
            relevant.append({"ref": f"{alt_prefix}xf{order}.def", "for_property": prop_id,
                             "alternative_origin": origin_id,
                             "static_definition_identity": semantic_identity,
                             "static_definition_identity_status": semantic_identity_status,
                             "trace_callee_identity": def_by_node[call_node]["trace_callee_identity"],
                             "trace_callee_identity_status": def_by_node[call_node]["trace_callee_identity_status"],
                             "definition_status": def_status,
                             "definition_node_id": (res or {}).get("def_node"),
                             "file": def_file, "line": def_line,
                             "provenance": ((locked or {}).get("provenance") or
                                            (res or {}).get("provenance") or
                                            ("TRACE_BACKED_EXACT_CALLEE"
                                             if def_status == "ESTABLISHED_BY_TRACE" else None)),
                             "code": def_code})
        else:
            relevant.append({"ref": f"{alt_prefix}xf{order}.callsite", "for_property": prop_id,
                             "alternative_origin": origin_id,
                             "call_node_id": call_node, "callee_name": callee_name,
                             "definition_status": "UNKNOWN",
                             "note": "transform body not statically resolved (semantic identity/definition unknown)"})


def build_evidence_v0():
    srcf = [r for r in rows("source_facts.tsv", 12) if r[4] == "ESTABLISHED"]
    tid = rows("transform_identity.tsv", 8)
    prop = rows("propagation_relations.tsv", 9)
    # identity-safe definition resolver output (separate producer), keyed by call node
    defres = {}
    for r in rows("definition_resolution.tsv", 8):
        defres[r[0]] = {"status": r[2], "def_node": r[3], "file": r[4], "line": r[5],
                        "provenance": r[6], "body": r[7]}
    # SECOND identity-establishment mechanism (Step 4): trace-backed exact-callee identity.
    # Established ONLY when the transform call is trace-linked to exactly one callee body; the
    # emitted body is the exact body handed to adjudication. No same-name inference.
    trace_id = {}
    for r in rows("trace_identity.tsv", 5):
        if r[0] == "call_node":
            continue
        trace_id[r[0]] = {"callee_fullName": r[1], "callee_id": r[2],
                          "unique": r[3] == "true", "body": r[4].replace("\\n", "\n")}
    # Optional third identity mechanism: exact dependency sources whose receiver identity was
    # established by the CPG and whose downloaded artifacts match package-lock integrity.
    # When the sidecar is absent, historical evidence and packets are unchanged.
    locked_res = {}
    for r in rows("locked_dependency_resolution.tsv", 9):
        locked_res[r[0]] = {"semantic_identity": r[1], "status": r[2],
                            "versions": json.loads(r[3]), "integrities": json.loads(r[4]), "lockfile": r[5],
                            "files": r[6], "provenance": r[7],
                            "body": r[8].replace("\\n", "\n").replace("\\\\", "\\")}
    if TARGET_SINK:
        srcf = [r for r in srcf if r[0] == TARGET_SINK]
    sink_node, sink_line = srcf[0][0], srcf[0][1]

    # FIX 1 (origin-aware per-alternative evidence targeting): each row of srcf is a DISTINCT
    # source->sink alternative (origin). `srcf[0]` must never be used as THE origin for semantic
    # review -- a candidate can have multiple alternatives with DIFFERENT property outcomes (one
    # BROKEN, another OPEN), and only the OPEN ones need semantic review; a BROKEN alternative is
    # already settled and showing its transforms would target the wrong evidence entirely (this
    # was measured on real Rocket.Chat code: 2/25 sampled candidates had a first-found origin whose
    # outcome differed from the candidate's correctly-joined outcome). ESTABLISHED alternatives
    # need no review either -- Step 6 resolves the candidate directly. So: build transform/
    # unresolved-property evidence ONLY for origins whose OWN property_outcome is OPEN.
    per_origin_outcome = {r[1]: r[2] for r in rows("property_outcome.tsv", 5) if r[0] == sink_node}
    open_origins = [o for o in srcf if per_origin_outcome.get(o[2]) == "OPEN"]

    transforms, unresolved, relevant = [], [], []
    def_by_node = {}
    # Property-id scoping: only prefix with the alternative index when there is genuinely more
    # than one OPEN alternative to disambiguate. This keeps property_id == "xf{N}.bounds_..."
    # (unprefixed) for the overwhelming common case of a single open alternative, preserving
    # backward compatibility with every existing hint file/fixture that targets that format.
    # Disambiguation is added ONLY when it is actually needed to avoid collisions.
    multi_open = len(open_origins) > 1
    for alt_idx, origin in enumerate(open_origins):
        pflow = next((p for p in prop if p[0] == sink_node and p[3] == origin[2]), None)
        origin_code = pflow[5] if pflow else ""
        origin_line = int(pflow[4]) if pflow and pflow[4].isdigit() else 0
        alt_prefix = f"o{alt_idx}." if multi_open else ""

        chain = sorted([t for t in tid if t[1] == origin[2]], key=lambda t: int(t[2]))
        relevant.append({"ref": f"{alt_prefix}origin.source", "alternative_origin": origin[2],
                         "line": origin_line, "code": origin_code, "node_id": origin[2],
                         "provenance": "propagation_relations (fact layer)"})
        _build_alternative_evidence(alt_prefix, origin[2], chain, defres, trace_id, locked_res,
                                     def_by_node, transforms, unresolved, relevant)
    relevant.append({"ref": "sink", "line": int(sink_line), "node_id": sink_node,
                     "kind": SINK_CALL_KIND, "sink_model": SINK_MODEL,
                     "downstream_primitive": PROPERTY_CONFIG["downstream_primitive"]})
    # code-by-node-id lookup, needed here AND by PATH_CODE_CONTEXT below -- built once, used twice,
    # so SOURCE_TO_SINK_PATHS can carry real code inline instead of forcing the reader (LLM or
    # human) to cross-reference a separate array by node_id to see what a path step actually is.
    ctx = {}
    for r in rows("path_code_context.tsv", 5):
        ctx[r[0]] = {"code": r[2], "containing_statement": r[3], "containing_function": r[4]}

    # SOURCE_TO_SINK_PATHS: one complete alternative per established origin, consumed from
    # production facts (source_facts + path-scoped transform identity + definition resolver).
    # Path steps are NOT reconstructed here; they are the fact-established path-member calls.
    # Each step now also carries its own code inline (callsite_code / containing_statement /
    # containing_function, and definition_body when trace-backed identity supplied one) -- the
    # SAME underlying facts PATH_CODE_CONTEXT uses, so the path is self-contained and readable
    # without jumping to a different top-level array.
    source_to_sink_paths = []
    for o in srcf:
        osrc, ofam = o[2], o[3]
        osteps = sorted([t for t in tid if t[1] == osrc], key=lambda t: int(t[2]))
        steps = []
        for t in osteps:
            cn = t[3]; r = defres.get(cn); auth = def_by_node.get(cn, {}); c = ctx.get(cn, {})
            steps.append({"path_order": int(t[2]), "node_id": cn, "node_kind": "CALL",
                          "callee_name": t[4] or None, "path_membership": "ESTABLISHED",
                          # two SEPARATE identity axes, named explicitly to avoid confusion:
                          "static_definition_identity": auth.get(
                              "static_definition_identity",
                              f"{t[5]}#{t[6]}" if t[7] == "ESTABLISHED" else None),
                          "static_definition_identity_status": auth.get(
                              "static_definition_identity_status", t[7]),
                          "trace_callee_identity": auth.get("trace_callee_identity"),
                          "trace_callee_identity_status": auth.get("trace_callee_identity_status", "NOT_ESTABLISHED"),
                          # authoritative (resolver OR trace-backed), matching the subject block
                          "definition_status": auth.get("definition_status",
                                               "ESTABLISHED" if (r and r["status"] == "ESTABLISHED") else "UNKNOWN"),
                          # the actual code, inline, not in a separate array requiring a node_id lookup:
                          "callsite_code": c.get("code"),
                          "containing_statement": c.get("containing_statement"),
                          "containing_function": c.get("containing_function"),
                          "definition_body": auth.get("definition_body"),
                          **({"locked_dependency_evidence": auth["locked_dependency_evidence"]}
                             if auth.get("locked_dependency_evidence") else {})})
        opflow = next((p for p in prop if p[0] == sink_node and p[3] == osrc), None)
        osc = ctx.get(osrc, {})
        source_to_sink_paths.append({
            "origin": {"origin_family": ofam, "source_node_id": osrc,
                       "source_code": opflow[5] if opflow else "",
                       "source_line": int(opflow[4]) if opflow and opflow[4].isdigit() else 0,
                       "source_containing_statement": osc.get("containing_statement"),
                       "source_containing_function": osc.get("containing_function"),
                       "established_by": "STATIC_PROVENANCE"},
            "steps": steps,
            "sink": sink_descriptor(sink_node, sink_line),
            "qualification": "ESTABLISHED_DATAFLOW", "necessity": "MAY_NOT_MUST"})

    # PATH_CODE_CONTEXT: kept as a richer, per-alternative view (definition bodies alongside
    # callsite code in one grouped structure) for anything that still wants that shape.
    # SOURCE_TO_SINK_PATHS above now also carries this same code inline per step, so a reader
    # no longer HAS to consult this section just to see what a path step is -- this remains
    # available as an additional, more narrative grouping, not the only place the code lives.
    # ctx built once above, reused here unchanged.
    path_code_context = []
    for path in source_to_sink_paths:
        osrc = path["origin"]["source_node_id"]
        sc = ctx.get(osrc, {})
        steps_ctx = []
        for st in path["steps"]:
            cn = st["node_id"]; c = ctx.get(cn, {}); auth = def_by_node.get(cn, {})
            steps_ctx.append({
                "path_order": st["path_order"], "call_node_id": cn,
                "callsite_code": c.get("code"), "containing_statement": c.get("containing_statement"),
                "containing_function": c.get("containing_function"),
                "callee_name": st["callee_name"], "definition_status": st["definition_status"],
                "definition_body": auth.get("definition_body")})
        snk = ctx.get(sink_node, {})
        path_code_context.append({
            "origin_source_node_id": osrc,
            "source": {"node_id": osrc, "expression": sc.get("code"),
                       "containing_statement": sc.get("containing_statement"),
                       "containing_function": sc.get("containing_function")},
            "steps": steps_ctx,
            "sink": {"node_id": sink_node, "expression": snk.get("code"),
                     "containing_statement": snk.get("containing_statement"),
                     "containing_function": snk.get("containing_function")}})

    # PATH_FLOW_CONTEXT: fact-established transitions BETWEEN path nodes (the reachableByFlows
    # dataflow edges), showing how the value moves through variables/args/params/returns/fields.
    # relation_kind is classified from CPG structure only; UNKNOWN when not established.
    # Intra-statement noise is collapsed: we keep each transition that ENTERS a new containing
    # statement or carries a non-UNKNOWN relation, so the sequence reads as the bridging code.
    flow = {}
    for r in rows("path_flow_context.tsv", 10):
        flow.setdefault((r[0], r[1]), []).append(
            {"seq": int(r[2]), "from_node_id": r[3], "to_node_id": r[4], "relation_kind": r[5],
             "from_expression": r[6], "to_expression": r[7],
             "containing_statement": r[8], "containing_function": r[9]})
    path_flow_context = []
    for path in source_to_sink_paths:
        osrc = path["origin"]["source_node_id"]
        trans = sorted(flow.get((sink_node, osrc), []), key=lambda x: x["seq"])
        kept = []; last_stmt = None
        for t in trans:
            if t["relation_kind"] != "UNKNOWN" or t["containing_statement"] != last_stmt:
                kept.append(t)
            last_stmt = t["containing_statement"]
        path_flow_context.append({"origin_source_node_id": osrc, "transitions": kept,
            # PATH_FLOW_CONTEXT is an OPTIONAL per-edge enrichment (from export_path_flow_context.sc).
            # Path membership itself is asserted in SOURCE_TO_SINK_PATHS; an empty list here means the
            # enrichment was not produced for this run, NOT that the path is absent.
            "transitions_status": ("ESTABLISHED" if kept else "NOT_PRODUCED"),
            "note": (None if kept else "optional flow-context enrichment not produced for this run; "
                     "path membership is asserted in SOURCE_TO_SINK_PATHS")})

    # SECURITY-PROPERTY PROPAGATION GATE (new validity layer; no frozen producer changed).
    # For serialize-DoS the tracked property is ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE.
    # The property producer classifies each edge's structural_relation SEPARATELY from its
    # property_effect, and reports a per-origin outcome. The candidate outcome is the best
    # surviving alternative (ESTABLISHED > OPEN > BROKEN):
    #   BROKEN      property definitely broken on every origin -> false positive, reject
    #   OPEN        property survival depends on an unresolved transform -> semantic review
    #   ESTABLISHED property preserved to the sink on some origin -> attacker controls size
    # Candidate outcome joins origins EXISTENTIALLY (one surviving origin establishes it).
    # NO_FLOW (no structural relation) is kept distinct from BROKEN (relation existed, property
    # destroyed) and OPEN (relation existed, semantics unmodeled) -- these must not be collapsed.
    def join_existential(ocs):
        if not ocs:                    return "NO_FLOW"
        if "ESTABLISHED" in ocs:       return "ESTABLISHED"
        if "OPEN" in ocs:              return "OPEN"
        if "BROKEN" in ocs:            return "BROKEN"
        return "NO_FLOW"
    outcome_present = (RAW / "property_outcome.tsv").exists()
    per_origin = [r for r in rows("property_outcome.tsv", 5) if r[0] == sink_node]
    if not outcome_present:
        candidate_outcome = "NOT_AUDITED"
    else:
        candidate_outcome = join_existential([r[2] for r in per_origin])
    property_name = PROPERTY_CONFIG["property_name"]
    value_preservation = {"ESTABLISHED": "ESTABLISHED", "OPEN": "OPEN",
                          "BROKEN": "NOT_ESTABLISHED", "NO_FLOW": "NO_FLOW",
                          "NOT_AUDITED": "NOT_AUDITED"}[candidate_outcome]
    if value_preservation in ("NOT_ESTABLISHED", "NO_FLOW"):
        unresolved = []                        # reject before semantic review; no LLM question

    # finding_id from production facts: repository/file (analyzed input) + sink node.
    finding_file = os.environ.get("TCH_FINDING", "report_handler.js")
    return {
        "schema": "canonical-evidence-set/js-ts/1.1",
        "finding_id": f"{PROPERTY_CONFIG['vulnerability_class']}:{finding_file}#sink{sink_node}",
        "note": "JS/TS candidate on real CPG + production fact producers",
        "sink": sink_descriptor(sink_node, sink_line),
        "deterministic_coverage": "SEMANTICALLY_OPEN",
        "disposition": "CANDIDATE_OPEN",
        "value_preservation": value_preservation,
        "security_property": property_name,
        "property_outcome": candidate_outcome,
        # An ESTABLISHED property means the MODELED security property reaches the sink. It is NOT
        # a confirmed vulnerability: the vulnerability-level questions below are out of scope for
        # TChecker and remain open.
        "property_vs_vulnerability": (
            {"established": PROPERTY_CONFIG["established_meaning"],
             "residual_vulnerability_questions": PROPERTY_CONFIG["residual_vulnerability_questions"]}
            if candidate_outcome == "ESTABLISHED" else None),
        "structural__ESTABLISHED_BY_STATIC_ANALYSIS": {
            # NARRATIVE SUMMARY ONLY (origin_family is typically identical across alternatives,
            # e.g. all "req.body"/"this.bodyParams") -- NOT used for semantic-review targeting or
            # disposition; that is per-alternative (see open_origins / _build_alternative_evidence).
            "origin": {"origin_family": srcf[0][3], "source_node_id": srcf[0][2],
                       "established_by": "STATIC_PROVENANCE",
                       "qualification": "ESTABLISHED_DATAFLOW(may; not proven necessary)"},
            "n_alternatives": len(srcf), "n_open_alternatives": len(open_origins),
            "transform_chain": transforms},
        "source_to_sink_paths": source_to_sink_paths,
        "path_code_context": path_code_context,
        "path_flow_context": path_flow_context,
        "semantically_unresolved__SEMANTICALLY_UNRESOLVED": unresolved,
        "not_applicable__NOT_APPLICABLE": [
            {"field": "control_effect", "reason": "no iteration/validation-control governs this sink"},
            {"field": "matcher_kind / domain_containment", "reason": "no denylist/predicate comparison"},
            {"field": "aliasing_scope", "reason": "no shared-object mutation"},
            {"field": "guard_disposition", "reason": "no control-flow guard dominates this sink"}],
        "relevant_code__RELEVANT_CODE": relevant,
    }


def is_resolved_break(p):
    """A property counts as a demonstrated BREAK only via a genuinely accepted SAFE hint (SAFE
    means: this transform bounds/breaks the property). DEFENSE IN DEPTH, same discipline as the
    abstention-collapse fix: this re-checks proposed_value itself rather than trusting
    adjudication_use alone, so an UNKNOWN-valued hint can never match here even if some future
    code path mis-sets adjudication_use."""
    h = p.get("semantic_hint")
    return p["adjudication_use"] == "ACCEPTED_HINT" and h and h.get("proposed_value") == "SAFE"


def is_resolved_survive(p):
    """A property counts as demonstrated SURVIVAL only via a genuinely accepted UNSAFE hint
    (UNSAFE means: attacker influence survives this transform). Same defense-in-depth re-check."""
    h = p.get("semantic_hint")
    return p["adjudication_use"] == "ACCEPTED_HINT" and h and h.get("proposed_value") == "UNSAFE"


def compose_alternative(alt_props):
    """Per-alternative composition (Fix 2): BREAKS anywhere on the alternative dominates (matches
    the frozen structural lattice's own BREAKS-dominant rule, applied at the semantic-review layer);
    else any remaining unresolved property keeps the alternative OPEN; else (every property has
    been demonstrated to survive) the alternative is ESTABLISHED. An UNKNOWN-valued or unanswered
    property is neither a break nor a survival -- it correctly falls into "remains OPEN"."""
    if any(is_resolved_break(p) for p in alt_props):
        return "BROKEN"
    if any(not is_resolved_break(p) and not is_resolved_survive(p) for p in alt_props):
        return "OPEN"
    return "ESTABLISHED"


def select_target(props):
    """Fix 2 target selection: path order is METADATA, not a gate. Reviews any adjudicable
    unresolved property in a still-live (not yet BROKEN or fully ESTABLISHED) alternative, without
    requiring an earlier unresolved property -- in the same or a different alternative -- to be
    answered first. Alternatives already settled (BROKEN by one property, or fully survived) stop
    consuming review entirely, since nothing about their remaining properties can change their
    already-determined outcome. Prefers an adjudicable property (exact body available) over a
    non-adjudicable one, so identity-blocked properties never crowd out reviewable evidence."""
    by_alt = {}
    for p in props:
        by_alt.setdefault(p.get("alternative_origin"), []).append(p)
    live = []
    for alt_props in by_alt.values():
        if any(is_resolved_break(p) for p in alt_props):
            continue   # alternative already BROKEN -- its other properties are moot
        if all(is_resolved_survive(p) for p in alt_props):
            continue   # alternative already fully ESTABLISHED -- nothing left to review
        for p in alt_props:
            if not is_resolved_break(p) and not is_resolved_survive(p) and p["semantic_hint"] is None:
                live.append(p)
    if not live:
        return None
    adjudicable = [p for p in live if p["definition_status"] in (
        "ESTABLISHED", "ESTABLISHED_BY_TRACE", "ESTABLISHED_BY_LOCKED_DEPENDENCY")]
    return adjudicable[0] if adjudicable else live[0]


def adjudicate(ev):
    # Property-propagation gate first. Three scientifically distinct rejections are preserved:
    #   NO_FLOW  -> no structural relation at all
    #   BROKEN   -> relation existed but the security property was demonstrably destroyed
    # (OPEN and ESTABLISHED proceed; OPEN reaches semantic review, ESTABLISHED is confirmed.)
    if ev.get("value_preservation") == "NO_FLOW":
        return "NOT_APPLICABLE", "REJECTED_NO_STRUCTURAL_FLOW"
    if ev.get("value_preservation") == "NOT_ESTABLISHED":
        return "NOT_APPLICABLE", "REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED"
    # Deterministic layer NEVER closes from hints: coverage stays OPEN while any property
    # is deterministically UNKNOWN. Disposition may still be reached using ACCEPTED hints,
    # but the underlying property is not rewritten as established.
    props = ev["semantically_unresolved__SEMANTICALLY_UNRESOLVED"]
    det_open = any(p["deterministic_status"] == "UNKNOWN" for p in props)
    det_coverage = "SEMANTICALLY_OPEN" if det_open else "SEMANTICALLY_CLOSED"
    # An ESTABLISHED security property is a CONFIRMED candidate: the property layer already proved
    # attacker control of serialized size/structure reaches the sink with no bounding transform.
    # This is distinct from OPEN (which genuinely needs semantic review) and must not be re-derived
    # from the transform-property model, which otherwise yields a vacuous SAFE (zero transforms) or
    # a spurious CANDIDATE_OPEN (an off-path transform such as a cache `.set()`).
    if ev.get("value_preservation") == "ESTABLISHED":
        return det_coverage, "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS"
    # FIX 2 (per-alternative composition, narrow scope): a property is "resolved" only via a
    # genuinely resolving accepted hint (SAME defense-in-depth check as before -- an UNKNOWN hint
    # can NEVER resolve a property, by construction of is_resolved_break/is_resolved_survive below,
    # since neither matches proposed_value=="UNKNOWN"). Composition is now done PER ALTERNATIVE
    # first (BREAKS dominant; else any unresolved -> OPEN; else all-survive -> ESTABLISHED), THEN
    # joined existentially across alternatives (any ESTABLISHED wins; else any OPEN keeps candidate
    # OPEN; else all-BROKEN -> SAFE). This is the SAME lattice and the SAME SAFE/UNSAFE/UNKNOWN
    # meanings as before -- only the SCOPE of composition changed, from one flat global list to
    # one composition per alternative. A BROKEN alternative can never suppress another alternative
    # that is still OPEN or has become ESTABLISHED (see multi-alternative regression suite).
    by_alt = {}
    for p in props:
        by_alt.setdefault(p.get("alternative_origin"), []).append(p)
    if not by_alt:
        return det_coverage, "CANDIDATE_OPEN"
    alt_states = [compose_alternative(alt_props) for alt_props in by_alt.values()]
    if "ESTABLISHED" in alt_states:
        return det_coverage, "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT"
    if "OPEN" in alt_states:
        return det_coverage, "CANDIDATE_OPEN"
    return det_coverage, "RESOLVED_SAFE_BY_ACCEPTED_HINT"


def hint_acceptance_rule(prop):
    """Decide how TChecker USES a hint in adjudication. This does NOT establish the
    property: deterministic_status stays UNKNOWN. It only sets adjudication_use.
    An UNKNOWN-valued hint (the model abstaining) is NEVER accepted, regardless of stated
    confidence: confidence describes how sure the model is of ITS ANSWER, and an abstention has
    no answer to be sure of. Accepting it would let adjudicate()'s "not UNSAFE -> SAFE" fallthrough
    silently promote a legitimate "I don't know" into a SAFE disposition — a false-negative risk."""
    h = prop.get("semantic_hint")
    if not h:
        prop["adjudication_use"] = None
    elif h.get("proposed_value") == "UNKNOWN":
        prop["adjudication_use"] = "NEEDS_MORE_REVIEW"
    elif h["confidence"] == "HIGH" and prop["subject_transform"] != "UNKNOWN":
        prop["adjudication_use"] = "ACCEPTED_HINT"        # usable for adjudication, still not a fact
    else:
        prop["adjudication_use"] = "NEEDS_MORE_REVIEW"
    return prop["adjudication_use"]


def render_audit_evidence(ev, target, round_no, prior_hints):
    """FULL audit evidence: all alternatives, all cross-referenceable arrays (SOURCE_TO_SINK_PATHS,
    PATH_CODE_CONTEXT, PATH_FLOW_CONTEXT, RELEVANT_CODE), redundant by design -- kept rich and
    reviewable for verification. This is NOT what gets sent to the LLM; see render_llm_packet for
    that. Saved as audit_evidence_N.json."""
    rel = [r for r in ev["relevant_code__RELEVANT_CODE"]
           if r.get("for_property") == target["property_id"] or r["ref"] == "sink"
           or (r.get("alternative_origin") == target.get("alternative_origin") and "origin.source" in r["ref"])]
    established_static = [{
        "fact": f"{ev['structural__ESTABLISHED_BY_STATIC_ANALYSIS']['origin']['origin_family']} input reaches the "
                f"sink through an established dataflow path",
        "established_by": "STATIC_PROVENANCE"}]

    # definition-aware question framing (rendering only) -- audit copy keeps the RELEVANT_CODE
    # wording since RELEVANT_CODE genuinely exists in THIS artifact (unlike the LLM packet below).
    name = target["callee_name"] or "<callee-name-unresolved>"
    base_q = target["focused_question"]
    if target["definition_status"] == "ESTABLISHED":
        question = (base_q + f" The uniquely resolved implementation of `{name}` is supplied in "
                    f"RELEVANT_CODE; answer the property about THAT implementation.")
    elif target["definition_status"] == "ESTABLISHED_BY_TRACE":
        question = (f"The transform `{name}` was not resolved by the static definition resolver, but an exact "
                    f"callee body was established by trace-backed identity and is supplied in RELEVANT_CODE "
                    f"(provenance TRACE_BACKED_EXACT_CALLEE); answer the property about THAT implementation. "
                    + base_q)
    elif target["definition_status"] == "ESTABLISHED_BY_LOCKED_DEPENDENCY":
        question = (f"The transform `{name}` was resolved through a receiver-proven, lockfile-integrity-backed "
                    f"dependency chain. The exact relevant chain is supplied in RELEVANT_CODE; answer the "
                    f"property about THAT implementation and configured build. " + base_q)
    else:
        question = (f"The implementation of `{name}` was not statically resolved. Based ONLY on the supplied "
                    f"evidence, determine whether the property can be established. Return UNKNOWN if the "
                    f"evidence is insufficient; do NOT infer behavior from the function name. " + base_q)

    return {
        "schema": "tchecker-audit-evidence/1.0", "round": round_no, "finding_id": ev["finding_id"],
        "sink": ev["sink"],
        "STATICALLY_ESTABLISHED": established_static,
        "SOURCE_TO_SINK_PATHS": ev["source_to_sink_paths"],       # graph/path facts, ALL alternatives
        "PATH_CODE_CONTEXT": ev["path_code_context"],              # actual code on those nodes
        "PATH_FLOW_CONTEXT": ev["path_flow_context"],              # code/relations connecting nodes
        "PRIOR_SEMANTIC_HINTS_ADVISORY": prior_hints,
        "STILL_NOT_DETERMINISTICALLY_ESTABLISHED": {
            "property_id": target["property_id"],
            "subject": {"call_node_id": target["subject_call_node"],
                        "alternative_origin": target.get("alternative_origin"),
                        "path_order": next(seg for seg in target["property_id"].split(".") if seg.startswith("xf"))[2:],
                        "callee_name": target["callee_name"], "callee_name_status": target["callee_name_status"],
                        "path_membership": "ESTABLISHED",
                        # two SEPARATE identity axes, named explicitly:
                        "static_definition_identity": target["semantic_identity"],
                        "static_definition_identity_status": target["semantic_identity_status"],
                        "trace_callee_identity": (target["subject_transform"]
                                                  if target["subject_transform"].startswith("TRACE:") else None),
                        "trace_callee_identity_status": ("ESTABLISHED"
                                                         if target["definition_status"] == "ESTABLISHED_BY_TRACE"
                                                         else "NOT_ESTABLISHED"),
                        "definition_status": target["definition_status"],
                        "body_supplied": target["definition_status"] in (
                            "ESTABLISHED", "ESTABLISHED_BY_TRACE", "ESTABLISHED_BY_LOCKED_DEPENDENCY")},
            "deterministic_status": "UNKNOWN"},
        "RELEVANT_CODE": rel,
        "QUESTION": question,
        "answer_contract": {"proposed_value": "SAFE | UNSAFE | UNKNOWN", "confidence": "LOW | MEDIUM | HIGH",
                            "source_must_be": "LLM", "rationale": "string",
                            "note": "This is a semantic HINT over unresolved semantics, not a fact."},
    }


def render_llm_packet(ev, target, round_no, prior_hints):
    """COMPACT, self-contained LLM packet: exactly ONE alternative (the one the unresolved
    property actually concerns -- not all alternatives, unlike the audit artifact), each on-path
    step carrying its own code exactly once (no PATH_CODE_CONTEXT cross-reference, no RELEVANT_CODE
    duplication), and a QUESTION that refers directly to the step's own definition_body rather than
    telling the reader to go look in a different array. This is what actually gets sent to the LLM;
    render_audit_evidence above remains available separately for verification. Saved as
    llm_input_N.json -- the historical name, kept stable since that's the file external tooling
    reads, even though its shape changed from the 1.4 schema."""
    alt_origin = target.get("alternative_origin")
    all_alts = ev["source_to_sink_paths"]
    alt_ref = next((p for p in all_alts if p["origin"]["source_node_id"] == alt_origin), None)
    if alt_ref is None and len(all_alts) == 1:
        alt_ref = all_alts[0]   # single-origin case: only one alternative exists at all
    assert alt_ref is not None, f"no matching alternative found for alternative_origin={alt_origin}"

    # copy (don't mutate the shared dict also used by render_audit_evidence) and enrich the sink
    # with its own code context -- expression/containing_statement/containing_function -- so the
    # alternative reads end-to-end (source code -> transform code -> sink code) with no outside
    # lookup, matching the same inline-code treatment already applied to source and steps.
    import copy as _copy
    alt = _copy.deepcopy(alt_ref)
    pcc_entry = next((e for e in ev["path_code_context"] if e["origin_source_node_id"] == alt_origin), None)
    if pcc_entry and pcc_entry.get("sink"):
        snk = pcc_entry["sink"]
        alt["sink"]["expression"] = snk.get("expression")
        alt["sink"]["containing_statement"] = snk.get("containing_statement")
        alt["sink"]["containing_function"] = snk.get("containing_function")

    subject_step = next((s for s in alt["steps"] if s["node_id"] == target["subject_call_node"]), None)
    path_order = next(seg for seg in target["property_id"].split(".") if seg.startswith("xf"))[2:]

    name = target["callee_name"] or "<callee-name-unresolved>"
    base_q = target["focused_question"]
    # question wording updated: refers to the step's OWN definition_body, never tells the reader
    # to consult a separate array -- there is no separate array in this packet to consult.
    if target["definition_status"] == "ESTABLISHED":
        question = (base_q + f" The uniquely resolved implementation of `{name}` is the "
                    f"definition_body already given on this alternative's step at path_order "
                    f"{path_order}; answer the property about THAT implementation.")
    elif target["definition_status"] == "ESTABLISHED_BY_TRACE":
        question = (f"The transform `{name}` was not resolved by the static definition resolver, but an exact "
                    f"callee body was established by trace-backed identity and is given as the definition_body "
                    f"on this alternative's step at path_order {path_order} (provenance "
                    f"TRACE_BACKED_EXACT_CALLEE); answer the property about THAT implementation. " + base_q)
    elif target["definition_status"] == "ESTABLISHED_BY_LOCKED_DEPENDENCY":
        question = (f"The transform `{name}` was resolved through a receiver-proven, lockfile-integrity-backed "
                    f"dependency chain. The exact relevant chain is the definition_body on this alternative's "
                    f"step at path_order {path_order}; answer the property about THAT implementation and "
                    f"configured build. " + base_q)
    else:
        question = (f"The implementation of `{name}` (step at path_order {path_order}) was not statically "
                    f"resolved and no trace-backed body is available. Based ONLY on the supplied evidence, "
                    f"determine whether the property can be established. Return UNKNOWN if the evidence is "
                    f"insufficient; do NOT infer behavior from the function name. " + base_q)

    return {
        "schema": "tchecker-llm-packet/1.0", "round": round_no, "finding_id": ev["finding_id"],
        "property_id": target["property_id"],
        "alternative": alt,   # ONE alternative only: origin (code inline) + steps (code inline) + sink
        "PRIOR_SEMANTIC_HINTS_ADVISORY": prior_hints,
        "unresolved_subject": {
            # points AT the step above by identity, does not repeat fields already on that step
            "call_node_id": target["subject_call_node"], "path_order": path_order,
            "deterministic_status": "UNKNOWN"},
        "QUESTION": question,
        "answer_contract": {"proposed_value": "SAFE | UNSAFE | UNKNOWN", "confidence": "LOW | MEDIUM | HIGH",
                            "source_must_be": "LLM", "rationale": "string",
                            "note": "This is a semantic HINT over unresolved semantics, not a fact."},
    }


def fold_hint(ev, prop_id, hint):
    for p in ev["semantically_unresolved__SEMANTICALLY_UNRESOLVED"]:
        if p["property_id"] == prop_id:
            p["semantic_hint"] = {"proposed_value": hint["proposed_value"], "confidence": hint["confidence"],
                                  "rationale": hint["rationale"], "source": "LLM"}
            p["hinted_by"] = "LLM"
            assert p["deterministic_status"] == "UNKNOWN"   # a hint never establishes the property
            hint_acceptance_rule(p)
    cov, disp = adjudicate(ev)
    ev["deterministic_coverage"], ev["disposition"] = cov, disp
    return ev


def save(name, obj):
    (OUT / name).write_text(json.dumps(obj, indent=2))


if __name__ == "__main__":
    for f in OUT.glob("*.json"):
        f.unlink()
    trace = {"schema": "adjudication-trace/1.1", "rounds": [], "fact_state_movement": []}

    ev = build_evidence_v0()
    cov, disp = adjudicate(ev)
    ev["deterministic_coverage"], ev["disposition"] = cov, disp
    save("evidence_v0.json", ev)
    trace["fact_state_movement"].append({"stage": "v0", "deterministic_coverage": cov, "disposition": disp})

    _hintfile = os.environ.get("TCH_HINTS")
    if _hintfile:
        injected = json.load(open(_hintfile))
    else:
      _suf = PROPERTY_CONFIG["property_id_suffix"]
      injected = {
        f"xf0.{_suf}":
            {"proposed_value": "SAFE", "confidence": "HIGH",
             "rationale": "clip() applies slice(0,64): the value is length-capped to 64 chars at this stage."},
        f"xf1.{_suf}":
            {"proposed_value": "UNSAFE", "confidence": "HIGH",
             "rationale": "wrap() builds { value, echo: v+v }: it duplicates the value and adds envelope keys, "
                          "imposing no length bound; the serialized output can still grow with attacker input."},
      }

    round_no, prior = 0, []
    while True:
        props = ev["semantically_unresolved__SEMANTICALLY_UNRESOLVED"]
        target = select_target(props)
        if target is None:
            break
        round_no += 1
        save(f"audit_evidence_{round_no}.json", render_audit_evidence(ev, target, round_no, list(prior)))
        save(f"llm_input_{round_no}.json", render_llm_packet(ev, target, round_no, list(prior)))

        if target["property_id"] not in injected:
            # no controlled hint available for this query -> emit the payload and stop.
            # (In deployment this is the point where the live model would be called.)
            break
        h = injected[target["property_id"]]
        save(f"hint_{round_no}.json", {"schema": "semantic-hint/1.0", "round": round_no,
             "property_id": target["property_id"], "subject_transform": target["subject_transform"],
             "proposed_value": h["proposed_value"], "confidence": h["confidence"],
             "rationale": h["rationale"], "source": "LLM"})
        prior.append({"property_id": target["property_id"], "proposed_value": h["proposed_value"],
                      "confidence": h["confidence"], "source": "LLM", "status": "advisory"})

        before = {p["property_id"]: (p["deterministic_status"], bool(p["semantic_hint"]), p["adjudication_use"]) for p in props}
        ev = fold_hint(ev, target["property_id"], h)
        after = {p["property_id"]: (p["deterministic_status"], bool(p["semantic_hint"]), p["adjudication_use"])
                 for p in ev["semantically_unresolved__SEMANTICALLY_UNRESOLVED"]}
        save(f"evidence_v{round_no}.json", ev)
        au = next(p for p in ev["semantically_unresolved__SEMANTICALLY_UNRESOLVED"]
                  if p["property_id"] == target["property_id"])["adjudication_use"]
        trace["rounds"].append({"round": round_no, "targeted": target["property_id"], "hint": h["proposed_value"],
                                "confidence": h["confidence"], "adjudication_use": au,
                                "note": "hint accepted FOR ADJUDICATION; property remains deterministically UNKNOWN"
                                if au == "ACCEPTED_HINT" else None})
        trace["fact_state_movement"].append({"stage": f"v{round_no}",
                                             "deterministic_coverage": ev["deterministic_coverage"],
                                             "disposition": ev["disposition"], "before": before, "after": after})

    save("evidence_final.json", ev)
    trace["final_disposition"] = ev["disposition"]
    trace["final_deterministic_coverage"] = ev["deterministic_coverage"]
    save("adjudication_trace.json", trace)

    print(f"rounds: {round_no}")
    for m in trace["fact_state_movement"]:
        print(f"  {m['stage']:4s} det_coverage={m['deterministic_coverage']:26s} disposition={m['disposition']}")
    print(f"FINAL: {ev['disposition']}  (deterministic layer: {ev['deterministic_coverage']})")
