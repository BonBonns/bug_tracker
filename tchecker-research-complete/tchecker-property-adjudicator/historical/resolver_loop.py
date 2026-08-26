#!/usr/bin/env python3
"""Iterative semantic-resolution proof (architecture question (a) only).

Proves the STATE MACHINE: a CanonicalEvidenceSet carries typed unknowns; each
review round injects a TYPED SemanticResolution (never simulated NL output);
the resolution folds into the state with its own provenance; deterministic
adjudication re-runs only when the semantic coverage is CLOSED for the finding's
question. Every established fact retains established_by (STATIC_ANALYSIS vs
SEMANTIC_REVIEW) and is never blurred into one pool.

This is separate from "how good is the LLM at supplying resolutions" — here the
resolutions are controlled inputs so the transition behavior is testable.
"""
import copy, json

# ---------- typed evidence state ----------
def initial_state(finding_id, transforms):
    """Build a CanonicalEvidenceSet with one UNKNOWN semantic property per
    unmodelled transform on the path (grounded in proof_propagation)."""
    semantic = {
        # statically established facts
        "input_origin": {"status": "ESTABLISHED", "value": "HTTP_BODY",
                         "established_by": "STATIC_ANALYSIS",
                         "provenance": "serialize_sinks.attacker_controlled + proof_propagation"},
        "sink_requires_bounded_depth": {"status": "ESTABLISHED", "value": True,
                                        "established_by": "STATIC_ANALYSIS",
                                        "provenance": "serialize_sinks.callee=JSON.stringify"},
        "source_transform_sink_relation": {"status": "ESTABLISHED", "value": transforms,
                                           "established_by": "STATIC_ANALYSIS",
                                           "provenance": "proof_propagation (relation-preservation producer)"},
        # NOT_APPLICABLE (not a gap)
        "xss_escaper_property": {"status": "NOT_APPLICABLE",
                                 "reason": "output-escaping irrelevant to serialize-DoS"},
    }
    # one UNKNOWN protective-property per transform
    unknowns = {}
    for t in transforms:
        prop = "bounds_nesting_depth" if t == "normalizeInput" else \
               ("imposes_max_payload_size" if t == "wrapperX" else "constrains_structure")
        key = f"transform::{t}::{prop}"
        semantic[key] = {"status": "UNKNOWN", "subject": t, "property": prop,
                         "security_role": "protective"}
        unknowns[key] = {"subject": t, "property": prop}
    return {"meta": {"finding_id": finding_id, "vuln_class": "SERIALIZE_DOS"},
            "semantic": semantic, "version": 0, "llm_queries": 0}


# ---------- typed semantic resolution + fold ----------
def make_resolution(subject, prop, value, established):
    """value in {True, False}; established in {True(=ESTABLISHED), False(=UNRESOLVED)}."""
    return {"subject": subject, "property": prop, "value": value,
            "status": "ESTABLISHED" if established else "UNRESOLVED",
            "established_by": "SEMANTIC_REVIEW",
            "provenance": "semantic-review round (typed injection)"}


def fold(state, resolution):
    """Fold a typed resolution into the evidence state -> new version. Never
    overwrites a STATIC_ANALYSIS fact; records established_by."""
    ns = copy.deepcopy(state)
    key = f"transform::{resolution['subject']}::{resolution['property']}"
    field = ns["semantic"].get(key)
    if field is None or field.get("status") == "NOT_APPLICABLE":
        return ns  # nothing to update / not applicable
    if resolution["status"] == "UNRESOLVED":
        # stays UNKNOWN; record the attempt but do not establish
        field["last_review"] = "UNRESOLVED"
    else:
        # UNKNOWN -> ESTABLISHED, carrying SEMANTIC_REVIEW provenance (not STATIC)
        field["status"] = "ESTABLISHED"
        field["value"] = resolution["value"]
        field["established_by"] = resolution["established_by"]
        field["provenance"] = resolution["provenance"]
    ns["version"] += 1
    return ns


# ---------- coverage + deterministic adjudication ----------
def required_unknowns(state):
    return [k for k, v in state["semantic"].items()
            if k.startswith("transform::") and v.get("status") == "UNKNOWN"]


def coverage(state):
    return "SEMANTICALLY_OPEN" if required_unknowns(state) else "SEMANTICALLY_CLOSED"


def adjudicate(state):
    """Deterministic verdict. Only decides when SEMANTICALLY_CLOSED. A single
    established protective transform property (True) clears the DoS; if every
    protective property resolved False (or none protect), the unguarded sink on
    attacker-controlled structure is CANDIDATE_REAL."""
    if coverage(state) == "SEMANTICALLY_OPEN":
        return {"verdict": "NEEDS_SEMANTIC_REVIEW", "required_unknowns": required_unknowns(state)}
    protective = [v for k, v in state["semantic"].items()
                  if k.startswith("transform::") and v.get("status") == "ESTABLISHED"]
    any_protects = any(v.get("value") is True for v in protective)
    if any_protects:
        return {"verdict": "CLEARED_SAFE",
                "reason": "a transform establishes the protective property required for this DoS mechanism"}
    return {"verdict": "CANDIDATE_REAL",
            "reason": "attacker controls raw nesting depth and no transform bounds it; unguarded JSON.stringify"}


# ---------- provenance-partitioned query rendering ----------
def render_query(state, target_key):
    def part(pred):
        return {k: v for k, v in state["semantic"].items() if pred(k, v)}
    statically = part(lambda k, v: v.get("established_by") == "STATIC_ANALYSIS")
    semantically_prior = part(lambda k, v: v.get("established_by") == "SEMANTIC_REVIEW"
                              and v.get("status") == "ESTABLISHED")
    tgt = state["semantic"][target_key]
    return {
        "STATICALLY_ESTABLISHED": {k: {"value": v.get("value")} for k, v in statically.items()},
        "SEMANTICALLY_ESTABLISHED_IN_PRIOR_REVIEW":
            {k: {"value": v.get("value")} for k, v in semantically_prior.items()},
        "STILL_UNRESOLVED_TARGET": {"subject": tgt["subject"], "property": tgt["property"]},
    }


# ---------- driver: the four required demonstrations ----------
def banner(t): print("\n" + "=" * 76 + f"\n{t}\n" + "=" * 76)

def show(state, label):
    verdict = adjudicate(state)
    print(f"  {label}: version=v{state['version']}  coverage={coverage(state)}  "
          f"llm_queries={state['llm_queries']}  verdict={verdict['verdict']}"
          + (f"  ({verdict.get('reason')})" if verdict.get('reason') else "")
          + (f"  required_unknowns={verdict.get('required_unknowns')}" if verdict.get('required_unknowns') else ""))


# CASE 1 — single unknown, resolves FALSE (unsafe) -> retain -> CANDIDATE_REAL
banner("CASE 1  single unknown, resolution = FALSE (transform does NOT bound depth)")
s0 = initial_state("transform.js:4", ["normalizeInput"]); show(s0, "v0 (before review)")
s0["llm_queries"] += 1
s1 = fold(s0, make_resolution("normalizeInput", "bounds_nesting_depth", value=False, established=True))
show(s1, "v1 (after fold)")
print("  => UNKNOWN -> ESTABLISHED(unsafe); additional_llm_queries after resolution = 0")

# CASE 2 — single unknown, resolves TRUE (protective) -> clear -> SAFE
banner("CASE 2  single unknown, resolution = TRUE (transform bounds depth)")
s0 = initial_state("transform.js:4", ["normalizeInput"]); show(s0, "v0")
s0["llm_queries"] += 1
s1 = fold(s0, make_resolution("normalizeInput", "bounds_nesting_depth", value=True, established=True))
show(s1, "v1")
print("  => UNKNOWN -> ESTABLISHED(protective); additional_llm_queries after resolution = 0")

# CASE 3 — single unknown, UNRESOLVED -> stays OPEN -> query again or abstain
banner("CASE 3  single unknown, review does NOT establish the property (UNRESOLVED)")
s0 = initial_state("transform.js:4", ["normalizeInput"]); show(s0, "v0")
s0["llm_queries"] += 1
s1 = fold(s0, make_resolution("normalizeInput", "bounds_nesting_depth", value=None, established=False))
show(s1, "v1 (after unresolved review)")
print("  => stays UNKNOWN; semantic=OPEN; policy: issue another targeted query OR abstain")
print("     (bounded review policy, e.g. max 2 rounds -> then ABSTAIN)")

# CASE 4 — two unknowns, v0 -> v1 -> v2 sharpening with provenance partitioning
banner("CASE 4  two unknowns (A: normalizeInput bounds nesting; B: wrapperX caps size)")
s0 = initial_state("twohop.js:6", ["normalizeInput", "wrapperX"]); show(s0, "v0")
print("  required unknown set:", required_unknowns(s0))
kA = "transform::normalizeInput::bounds_nesting_depth"
kB = "transform::wrapperX::imposes_max_payload_size"

# round 1: query A
print("\n  -- round 1: targeted query for A --")
print("  query payload provenance partition:")
print("   ", json.dumps(render_query(s0, kA), indent=2).replace("\n", "\n    "))
s0["llm_queries"] += 1
s1 = fold(s0, make_resolution("normalizeInput", "bounds_nesting_depth", value=False, established=True))
show(s1, "v1"); print("  required unknown set now:", required_unknowns(s1),
                       "  <- reduced, NOT merely retried")

# round 2: query B, carrying A forward as SEMANTICALLY_ESTABLISHED_IN_PRIOR_REVIEW
print("\n  -- round 2: targeted query for B (A carried forward with its provenance) --")
print("  query payload provenance partition:")
print("   ", json.dumps(render_query(s1, kB), indent=2).replace("\n", "\n    "))
s1["llm_queries"] += 1
s2 = fold(s1, make_resolution("wrapperX", "imposes_max_payload_size", value=True, established=True))
show(s2, "v2 (final)")
print("  required unknown set now:", required_unknowns(s2))
print("\n  final evidence — established_by is preserved per fact (never blurred):")
for k, v in s2["semantic"].items():
    if v.get("status") == "ESTABLISHED":
        print(f"    {k:52s} value={v.get('value')!s:6s} by={v['established_by']}")
