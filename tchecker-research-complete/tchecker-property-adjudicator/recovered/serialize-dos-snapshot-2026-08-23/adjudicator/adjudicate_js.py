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
    if TARGET_SINK:
        srcf = [r for r in srcf if r[0] == TARGET_SINK]
    sink_node, sink_line = srcf[0][0], srcf[0][1]
    origin = srcf[0]
    # origin display coordinates come from the FACT layer (propagation source_code/source_line)
    pflow = next((p for p in prop if p[0] == sink_node and p[3] == origin[2]), None)
    origin_code = pflow[5] if pflow else ""
    origin_line = int(pflow[4]) if pflow and pflow[4].isdigit() else 0

    chain = sorted([t for t in tid if t[1] == origin[2]], key=lambda t: int(t[2]))
    transforms, unresolved, relevant = [], [], []
    relevant.append({"ref": "origin.source", "line": origin_line,
                     "code": origin_code, "node_id": origin[2],
                     "provenance": "propagation_relations (fact layer)"})
    for t in chain:
        order, call_node, callee, spec, member, status = t[2], t[3], t[4], t[5], t[6], t[7]
        # callee_name is a call FACT (ESTABLISHED) and is independent of semantic identity.
        callee_name = callee if callee else None
        callee_name_status = "ESTABLISHED" if callee_name else "UNKNOWN"
        semantic_identity = f"{spec}#{member}" if status == "ESTABLISHED" else None
        semantic_identity_status = status  # ESTABLISHED | UNKNOWN
        # definition body comes from the identity-safe definition resolver, OR — when that is
        # UNKNOWN — from the trace-backed exact-callee identity (Step 4), which supplies the same
        # unique body it identified. Trace identity is used ONLY when unique.
        def_status, def_file, def_line, def_code = "UNKNOWN", None, None, None
        res = defres.get(call_node)
        tr = trace_id.get(call_node)
        trace_established = bool(tr and tr["unique"])
        if res and res["status"] == "ESTABLISHED":
            def_status = "ESTABLISHED"
            def_file, def_line, def_code = res["file"], res["line"], res["body"]
            identity = semantic_identity if semantic_identity else "UNKNOWN"
        elif trace_established:
            # exact-callee identity from actual trace entry; exact body supplied to adjudication
            def_status = "ESTABLISHED_BY_TRACE"
            def_code = tr["body"]
            identity = "TRACE:" + tr["callee_fullName"]
        else:
            identity = semantic_identity if semantic_identity else "UNKNOWN"
        transforms.append({"order": int(order), "call_node": call_node,
                           "callee_name": callee_name, "callee_name_status": callee_name_status,
                           "semantic_identity": semantic_identity,
                           "semantic_identity_status": semantic_identity_status,
                           "definition_status": def_status,
                           "established_by": "STATIC_PROVENANCE_IDENTITY_JOIN" if status == "ESTABLISHED" else None})
        prop_id = f"xf{order}.bounds_serialized_size"
        name_disp = callee_name if callee_name else "<callee-name-unresolved>"
        unresolved.append({
            "property_id": prop_id,
            "subject_transform": identity, "subject_call_node": call_node,   # kept for the unchanged rule
            "callee_name": callee_name, "callee_name_status": callee_name_status,
            "semantic_identity": semantic_identity, "semantic_identity_status": semantic_identity_status,
            "definition_status": def_status,
            "deterministic_status": "UNKNOWN",
            "semantic_hint": None,
            "adjudication_use": None,
            "focused_question": (f"Does the on-path call `{name_disp}` at path position {order} "
                                 f"(semantic identity {semantic_identity_status}) bound the serialized size of the "
                                 f"value, or can attacker influence remain effectively unbounded?")})
        # relevant_code carries the transform body only when the definition relation is established;
        # otherwise callsite only, explicitly flagged as not statically resolved.
        if def_status in ("ESTABLISHED", "ESTABLISHED_BY_TRACE"):
            relevant.append({"ref": f"xf{order}.def", "for_property": prop_id,
                             "semantic_identity": semantic_identity,
                             "definition_status": def_status,
                             "definition_node_id": (res or {}).get("def_node"),
                             "file": def_file, "line": def_line,
                             "provenance": (res or {}).get("provenance") or ("TRACE_BACKED_EXACT_CALLEE"
                                            if def_status == "ESTABLISHED_BY_TRACE" else None),
                             "code": def_code})
        else:
            relevant.append({"ref": f"xf{order}.callsite", "for_property": prop_id,
                             "call_node_id": call_node, "callee_name": callee_name,
                             "definition_status": "UNKNOWN",
                             "note": "transform body not statically resolved (semantic identity/definition unknown)"})
    relevant.append({"ref": "sink", "line": int(sink_line), "node_id": sink_node,
                     "kind": "JSON.stringify"})

    # SOURCE_TO_SINK_PATHS: one complete alternative per established origin, consumed from
    # production facts (source_facts + path-scoped transform identity + definition resolver).
    # Path steps are NOT reconstructed here; they are the fact-established path-member calls.
    source_to_sink_paths = []
    for o in srcf:
        osrc, ofam = o[2], o[3]
        osteps = sorted([t for t in tid if t[1] == osrc], key=lambda t: int(t[2]))
        steps = []
        for t in osteps:
            cn = t[3]; r = defres.get(cn)
            steps.append({"path_order": int(t[2]), "node_id": cn, "node_kind": "CALL",
                          "callee_name": t[4] or None, "path_membership": "ESTABLISHED",
                          "semantic_identity": (f"{t[5]}#{t[6]}" if t[7] == "ESTABLISHED" else None),
                          "semantic_identity_status": t[7],
                          "definition_status": ("ESTABLISHED" if (r and r["status"] == "ESTABLISHED") else "UNKNOWN")})
        opflow = next((p for p in prop if p[0] == sink_node and p[3] == osrc), None)
        source_to_sink_paths.append({
            "origin": {"origin_family": ofam, "source_node_id": osrc,
                       "source_code": opflow[5] if opflow else "",
                       "source_line": int(opflow[4]) if opflow and opflow[4].isdigit() else 0,
                       "established_by": "STATIC_PROVENANCE"},
            "steps": steps,
            "sink": {"node_id": sink_node, "line": int(sink_line), "kind": "JSON.stringify"},
            "qualification": "ESTABLISHED_DATAFLOW", "necessity": "MAY_NOT_MUST"})

    # PATH_CODE_CONTEXT: actual code attached to established path nodes (by node id only).
    # Separate layer from SOURCE_TO_SINK_PATHS (graph facts). Definition bodies come from the
    # frozen definition resolver; callsite/source/sink code from path_code_context facts.
    ctx = {}
    for r in rows("path_code_context.tsv", 5):
        ctx[r[0]] = {"code": r[2], "containing_statement": r[3], "containing_function": r[4]}
    path_code_context = []
    for path in source_to_sink_paths:
        osrc = path["origin"]["source_node_id"]
        sc = ctx.get(osrc, {})
        steps_ctx = []
        for st in path["steps"]:
            cn = st["node_id"]; c = ctx.get(cn, {}); r = defres.get(cn)
            steps_ctx.append({
                "path_order": st["path_order"], "call_node_id": cn,
                "callsite_code": c.get("code"), "containing_statement": c.get("containing_statement"),
                "containing_function": c.get("containing_function"),
                "callee_name": st["callee_name"], "definition_status": st["definition_status"],
                "definition_body": (r["body"] if (r and r["status"] == "ESTABLISHED") else None)})
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
        path_flow_context.append({"origin_source_node_id": osrc, "transitions": kept})

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
    property_name = "ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE"
    value_preservation = {"ESTABLISHED": "ESTABLISHED", "OPEN": "OPEN",
                          "BROKEN": "NOT_ESTABLISHED", "NO_FLOW": "NO_FLOW",
                          "NOT_AUDITED": "NOT_AUDITED"}[candidate_outcome]
    if value_preservation in ("NOT_ESTABLISHED", "NO_FLOW"):
        unresolved = []                        # reject before semantic review; no LLM question

    # finding_id from production facts: repository/file (analyzed input) + sink node.
    finding_file = os.environ.get("TCH_FINDING", "report_handler.js")
    return {
        "schema": "canonical-evidence-set/js-ts/1.1",
        "finding_id": f"serialize-dos:{finding_file}#sink{sink_node}",
        "note": "JS/TS candidate on real CPG + production fact producers",
        "sink": {"node_id": sink_node, "line": int(sink_line), "kind": "JSON.stringify", "class": "serialize-dos"},
        "deterministic_coverage": "SEMANTICALLY_OPEN",
        "disposition": "CANDIDATE_OPEN",
        "value_preservation": value_preservation,
        "security_property": property_name,
        "property_outcome": candidate_outcome,
        # An ESTABLISHED property means the MODELED security property (attacker control of
        # serialized size/structure) reaches the sink. It is NOT a confirmed vulnerability: the
        # vulnerability-level questions below are out of scope for TChecker and remain open.
        "property_vs_vulnerability": (
            {"established": "modeled security property only (not a confirmed DoS)",
             "residual_vulnerability_questions": ["effective request-size bounds (e.g. body-parser limits)",
                                                  "reachability of the handler", "repeatability",
                                                  "actual resource impact"]}
            if candidate_outcome == "ESTABLISHED" else None),
        "structural__ESTABLISHED_BY_STATIC_ANALYSIS": {
            "origin": {"origin_family": origin[3], "source_node_id": origin[2],
                       "established_by": "STATIC_PROVENANCE",
                       "qualification": "ESTABLISHED_DATAFLOW(may; not proven necessary)"},
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
    # a property is adjudicable iff deterministically established OR its hint is accepted
    not_adjudicable = [p for p in props if p["deterministic_status"] == "UNKNOWN"
                       and p["adjudication_use"] != "ACCEPTED_HINT"]
    if not_adjudicable:
        return det_coverage, "CANDIDATE_OPEN"
    unsafe = [p for p in props if p["adjudication_use"] == "ACCEPTED_HINT"
              and p.get("semantic_hint") and p["semantic_hint"]["proposed_value"] == "UNSAFE"]
    if unsafe:
        return det_coverage, "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT"
    return det_coverage, "RESOLVED_SAFE_BY_ACCEPTED_HINT"


def hint_acceptance_rule(prop):
    """Decide how TChecker USES a hint in adjudication. This does NOT establish the
    property: deterministic_status stays UNKNOWN. It only sets adjudication_use."""
    h = prop.get("semantic_hint")
    if not h:
        prop["adjudication_use"] = None
    elif h["confidence"] == "HIGH" and prop["subject_transform"] != "UNKNOWN":
        prop["adjudication_use"] = "ACCEPTED_HINT"        # usable for adjudication, still not a fact
    else:
        prop["adjudication_use"] = "NEEDS_MORE_REVIEW"
    return prop["adjudication_use"]


def render_llm_input(ev, target, round_no, prior_hints):
    rel = [r for r in ev["relevant_code__RELEVANT_CODE"]
           if r.get("for_property") == target["property_id"] or r["ref"] in ("origin.source", "sink")]
    established_static = [{
        "fact": f"{ev['structural__ESTABLISHED_BY_STATIC_ANALYSIS']['origin']['origin_family']} input reaches the "
                f"sink through an established dataflow path",
        "established_by": "STATIC_PROVENANCE"}]

    # definition-aware question framing (rendering only)
    name = target["callee_name"] or "<callee-name-unresolved>"
    base_q = target["focused_question"]
    if target["definition_status"] == "ESTABLISHED":
        question = (base_q + f" The uniquely resolved implementation of `{name}` is supplied in "
                    f"RELEVANT_CODE; answer the property about THAT implementation.")
    else:
        question = (f"The implementation of `{name}` was not statically resolved. Based ONLY on the supplied "
                    f"evidence, determine whether the property can be established. Return UNKNOWN if the "
                    f"evidence is insufficient; do NOT infer behavior from the function name. " + base_q)

    return {
        "schema": "tchecker-llm-input/1.3", "round": round_no, "finding_id": ev["finding_id"], "sink": ev["sink"],
        "STATICALLY_ESTABLISHED": established_static,
        "SOURCE_TO_SINK_PATHS": ev["source_to_sink_paths"],       # graph/path facts
        "PATH_CODE_CONTEXT": ev["path_code_context"],              # actual code on those nodes
        "PATH_FLOW_CONTEXT": ev["path_flow_context"],              # code/relations connecting nodes
        "PRIOR_SEMANTIC_HINTS_ADVISORY": prior_hints,
        "STILL_NOT_DETERMINISTICALLY_ESTABLISHED": {
            "property_id": target["property_id"],
            "subject": {"call_node_id": target["subject_call_node"], "path_order": target["property_id"].split(".")[0][2:],
                        "callee_name": target["callee_name"], "callee_name_status": target["callee_name_status"],
                        "path_membership": "ESTABLISHED",
                        "semantic_identity": target["semantic_identity"],
                        "semantic_identity_status": target["semantic_identity_status"],
                        "definition_status": target["definition_status"],
                        "body_supplied": target["definition_status"] == "ESTABLISHED"},
            "deterministic_status": "UNKNOWN"},
        "RELEVANT_CODE": rel,
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
      injected = {
        "xf0.bounds_serialized_size":
            {"proposed_value": "SAFE", "confidence": "HIGH",
             "rationale": "clip() applies slice(0,64): the value is length-capped to 64 chars at this stage."},
        "xf1.bounds_serialized_size":
            {"proposed_value": "UNSAFE", "confidence": "HIGH",
             "rationale": "wrap() builds { value, echo: v+v }: it duplicates the value and adds envelope keys, "
                          "imposing no length bound; the serialized output can still grow with attacker input."},
      }

    round_no, prior = 0, []
    while True:
        props = ev["semantically_unresolved__SEMANTICALLY_UNRESOLVED"]
        target = next((p for p in props if p["deterministic_status"] == "UNKNOWN"
                       and p["adjudication_use"] != "ACCEPTED_HINT" and p["semantic_hint"] is None), None)
        if target is None:
            break
        round_no += 1
        save(f"llm_input_{round_no}.json", render_llm_input(ev, target, round_no, list(prior)))

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
