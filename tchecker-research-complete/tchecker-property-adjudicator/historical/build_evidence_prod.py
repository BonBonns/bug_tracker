#!/usr/bin/env python3
"""PROOF adapter: real CPG facts -> CanonicalEvidenceSet -> semantic question ->
rendered LLM input. Validates the four-part architecture on serialize-DoS.

Consumes ONLY typed JS/TS facts (no ts2legacycsv, no PHP nodes.csv):
  serialize_sinks.tsv    (sink family + local mitigations)
  proof_propagation.tsv  (source -> transform? -> sink relation)
  require_bindings.tsv    (module identity of a transform)

Demonstrates:
  * tri-state semantic fields (ESTABLISHED / UNKNOWN / NOT_APPLICABLE) with provenance
  * deterministic triage: rule a candidate in/out WITHOUT an LLM when possible
  * for a survivor, a FOCUSED semantic question + rendered LLM input containing
    established semantics + one explicit unknown (not just a path)
"""
import json, sys
from pathlib import Path

RAW = Path(sys.argv[1] if len(sys.argv) > 1 else "proof-out/raw")
SRC_ROOT = Path(sys.argv[2] if len(sys.argv) > 2 else "proof-src")


def rows(name, n):
    p = RAW / name
    if not p.exists():
        return []
    return [ln.split("\t") for ln in p.read_text().splitlines() if ln.strip() and len(ln.split("\t")) == n]


def line_code(file_rel, line):
    # file paths in facts are like 'direct.js'; source lives under SRC_ROOT
    for cand in (SRC_ROOT / file_rel, SRC_ROOT / Path(file_rel).name):
        if cand.exists():
            ls = cand.read_text().splitlines()
            if 1 <= int(line) <= len(ls):
                return ls[int(line) - 1].strip()
    return "(unreadable)"


def fn_body(name):
    for f in SRC_ROOT.glob("*.js"):
        t = f.read_text()
        i = t.find(f"function {name}")
        if i >= 0:
            j = t.find("{", i); depth = 0
            for k in range(j, len(t)):
                if t[k] == "{": depth += 1
                elif t[k] == "}":
                    depth -= 1
                    if depth == 0:
                        return t[i:k + 1]
    return None


sinks = {(r[0], r[2]): r for r in rows("serialize_sinks.tsv", 8)}          # (file,line)->row
# PRODUCTION propagation facts (DDG-based), keyed by sink line -> (origin_kind, transforms)
_prod = rows("propagation_relations.tsv", 9)
prop = {}
for r in _prod:
    if r[2] != "ESTABLISHED": continue
    trs = [seg.split(":")[2] for seg in r[6].split(" ; ") if seg]
    origin = "DIRECT_BODY" if not trs else "VIA_TRANSFORM"
    prop[r[1]] = {"origin": origin, "transforms": trs, "source_code": r[5], "provenance": r[8]}
reqb = rows("require_bindings.tsv", 4)                                       # module identity


def module_identity_of(transform_name, file_):
    # transform resolves to which module? from require_bindings (local<-require(spec))
    # here the transform is imported: `const { normalizeInput } = require('./normalizer')`
    for r in reqb:
        if r[0] == file_ or Path(r[0]).name == Path(file_).name:
            # r = file, spec, local, methodid  — the spec is the resolved module
            return {"module": r[1], "provenance": "module_export_identity.sc (R14) require_bindings"}
    return None


def build_evidence(file_, line):
    s = sinks[(file_, line)]
    p_ = prop.get(line)
    _, _, _, callee, argc, attacker, in_try, bounded = s
    origin_kind = p_["origin"] if p_ else "OTHER"
    transform_name = (p_["transforms"][0] if (p_ and p_["transforms"]) else "")

    # ---- 1. STRUCTURAL ----
    structural = {
        "source_location": {"file": file_, "code": (p_["source_code"] if p_ else argc),
                            "provenance": (p_["provenance"] if p_ else "serialize_sinks")},
        "propagation": ([{"step": "source"},
                         {"step": "transform", "fn": transform_name}] if origin_kind == "VIA_TRANSFORM"
                        else [{"step": "source->sink direct"}]),
        "sink_location": {"file": file_, "line": int(line), "code": line_code(file_, line)},
        "sink_family": "SERIALIZE_JSON_STRINGIFY",
    }

    # ---- 2. SEMANTIC (tri-state, with provenance for ESTABLISHED) ----
    input_origin = {"status": "ESTABLISHED", "value": "HTTP_BODY",
                    "provenance": "attacker_controlled=true on serialize_sinks; "
                                  "arg traces to request.body (proof_propagation)"} \
        if attacker == "true" else {"status": "UNKNOWN"}

    # the DoS-relevant property: can the attacker control nesting DEPTH of the
    # serialized value? For a DIRECT body it is ESTABLISHED yes; via an unmodelled
    # transform it is UNKNOWN (does the transform bound depth?).
    if origin_kind == "DIRECT_BODY":
        depth_control = {"status": "ESTABLISHED", "value": "attacker-controlled (raw request.body)",
                         "provenance": "propagation_relations (DDG, reachableByFlows)"}
        transform_sem = {"status": "NOT_APPLICABLE", "reason": "no transform on path"}
    elif origin_kind == "VIA_TRANSFORM":
        mid = module_identity_of(transform_name, file_)
        transform_sem = {"status": "UNKNOWN", "transform": transform_name,
                         "module_identity": mid,   # module identity IS established...
                         "unknown_property": "does it bound nesting depth / constrain structure?"}
        depth_control = {"status": "UNKNOWN",
                         "reason": f"depends on unmodelled semantics of {transform_name}()"}
    else:
        depth_control = {"status": "UNKNOWN"}; transform_sem = {"status": "UNKNOWN"}

    # local mitigations as tri-state
    sanitizer_depth_guard = {"status": "ESTABLISHED", "value": "depth guard present",
                             "provenance": "depth_guards"} if False else \
        ({"status": "ESTABLISHED", "value": "bounded object literal",
          "provenance": "serialize_sinks bounded_literal=true"} if bounded == "true"
         else {"status": "UNKNOWN" if origin_kind == "VIA_TRANSFORM" else "ESTABLISHED",
               "value": None if origin_kind == "VIA_TRANSFORM" else "no depth bound established",
               **({"provenance": "serialize_sinks: no try/catch, no depth_guard, not bounded"}
                  if origin_kind != "VIA_TRANSFORM" else {})})
    # error-catch net (does NOT mitigate DoS, tracked for coverage only)
    try_net = {"status": "ESTABLISHED", "value": ("in_try_catch" if in_try == "true" else "no try/catch"),
               "note": "try/catch does not mitigate a synchronous RangeError DoS",
               "provenance": "serialize_sinks in_try_catch"}

    # a field that is genuinely irrelevant to THIS class -> NOT_APPLICABLE (R1)
    xss_escaper = {"status": "NOT_APPLICABLE",
                   "reason": "output-escaping is irrelevant to a serialize-DoS finding"}

    semantic = {
        "input_origin": input_origin,
        "sink_semantics": {"status": "ESTABLISHED", "sink_family": "SERIALIZE_JSON_STRINGIFY",
                           "required_property": "input nesting depth must be bounded",
                           "provenance": "serialize_sinks callee=JSON.stringify"},
        "attacker_depth_control": depth_control,
        "transform_semantics": transform_sem,
        "sanitizer_property(depth_bound)": sanitizer_depth_guard,
        "error_net": try_net,
        "xss_escaper_property": xss_escaper,
    }

    # ---- 3. UNCERTAINTY ----
    # required-to-decide properties for THIS question: attacker_depth_control.
    required_unknowns = []
    if depth_control["status"] == "UNKNOWN":
        required_unknowns.append("attacker_depth_control")
    if transform_sem.get("status") == "UNKNOWN":
        required_unknowns.append("transform_semantics")

    structurally_closed = True  # source, sink, and (module) identities are established
    semantically_open = len(required_unknowns) > 0
    coverage = ("SEMANTICALLY_OPEN" if semantically_open
                else "SEMANTICALLY_CLOSED")  # relative to the DoS question (R2)

    questions = []
    if semantically_open and origin_kind == "VIA_TRANSFORM":
        questions.append(
            f"Does {transform_name}() bound the nesting depth of its input (or otherwise "
            f"constrain attacker control over the serialized structure) enough to prevent "
            f"JSON.stringify from exceeding the call-stack limit? The transform's module "
            f"identity is established ({transform_name} <- required module); only its "
            f"depth-bounding SECURITY PROPERTY is unresolved.")

    uncertainty = {
        "coverage_state": {"structural": "STRUCTURALLY_CLOSED",
                           "semantic": coverage,
                           "required_unknowns": required_unknowns},
        "semantic_questions": questions,
    }

    # ---- 4. RELEVANT CODE (only what answers the open question) ----
    bodies = []
    if origin_kind == "VIA_TRANSFORM":
        b = fn_body(transform_name)
        if b:
            bodies.append({"fn": transform_name, "why": "its depth-bounding property is the open question",
                           "body": b})
    bodies.append({"fn": "sink line", "body": line_code(file_, line)})

    return {
        "meta": {"finding_id": f"{Path(file_).name}:{line}", "vuln_class": "SERIALIZE_DOS", "language": "js"},
        "structural_evidence": structural,
        "semantic_evidence": semantic,
        "uncertainty": uncertainty,
        "relevant_code": bodies,
    }, coverage, origin_kind


# ---------- deterministic triage + rendering ----------
LLM_SYS = ("You perform SEMANTIC REVIEW of a security candidate that deterministic "
           "analysis could NOT resolve on its own. You are given: (1) established "
           "structural + semantic facts (treat as authoritative, do not rediscover), "
           "and (2) exactly the unresolved semantic question(s). Answer ONLY the "
           "unresolved question from the provided code. Reply compact JSON: "
           '{"resolves":"YES|NO|UNSURE","property":"<what the transform establishes, or null>",'
           '"reason":"<=30 words"}.')

print("=" * 78)
for (file_, line) in sorted(sinks):
    ev, coverage, origin = build_evidence(file_, line)
    fid = ev["meta"]["finding_id"]
    if coverage == "SEMANTICALLY_CLOSED" and origin == "DIRECT_BODY":
        # deterministic rule-in: attacker controls raw structure, unguarded sink -> REAL, NO LLM
        print(f"[{fid}] DETERMINISTIC verdict = CANDIDATE_REAL "
              f"(attacker controls raw nesting depth; unguarded JSON.stringify). "
              f"coverage={coverage}. -> NO LLM INPUT GENERATED.\n")
        continue
    # survivor: generate the focused LLM input
    user = ("Established facts (authoritative):\n" +
            json.dumps({"structural": ev["structural_evidence"],
                        "semantic": {k: v for k, v in ev["semantic_evidence"].items()
                                     if v.get("status") == "ESTABLISHED"}}, indent=2) +
            "\n\nNOT_APPLICABLE (do not treat as gaps):\n" +
            json.dumps([k for k, v in ev["semantic_evidence"].items()
                        if v.get("status") == "NOT_APPLICABLE"]) +
            "\n\nUNRESOLVED SEMANTIC QUESTION:\n" +
            "\n".join(ev["uncertainty"]["semantic_questions"]) +
            "\n\nRELEVANT CODE:\n" +
            "\n".join(f"--- {b['fn']} ---\n{b['body']}" for b in ev["relevant_code"]))
    payload = {"messages": [{"role": "system", "content": LLM_SYS},
                            {"role": "user", "content": user}]}
    print(f"[{fid}] SURVIVES deterministic analysis. coverage={coverage}.")
    print(f"        required_unknowns = {ev['uncertainty']['coverage_state']['required_unknowns']}")
    print(f"        -> GENERATED LLM INPUT (focused semantic question):\n")
    print(json.dumps(payload, indent=2))
    print()
    # also emit the full evidence object for inspection
    Path("/tmp/evidence_%s.json" % fid.replace(":", "_")).write_text(json.dumps(ev, indent=2))
print("=" * 78)
