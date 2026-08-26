#!/usr/bin/env python3
"""R-next control #6 (thesis-critical): per-alternative semantic closure.

Multiple established origins are independent ALTERNATIVES. A security question is
SEMANTICALLY_CLOSED only when the required property is resolved for EVERY relevant
established alternative. Resolving a semantic property on one branch must NOT be
silently applied to another, and must NOT clear the whole candidate while another
alternative remains unresolved or unsafe.

Scenario (from the mo-fixture m6, two established origins to one sink):
    HTTP_BODY  -> sanitizerX -> sink     (protective property UNKNOWN)
    HTTP_QUERY ------------->  sink       (direct; no transform to bound it)

Typed resolutions are injected (no live LLM), so the state transition is testable.
"""
import copy, json


def initial_state():
    # each alternative = one established origin path, with its own required property
    return {
        "finding": "m6:JSON.stringify (2 established origins)",
        "alternatives": [
            {"id": "A", "origin_family": "HTTP_BODY", "source_node": "…119",
             "path": ["sanitizerX"], "transform_property": "bounds_depth",
             "status": "UNKNOWN", "established_by": None},
            {"id": "B", "origin_family": "HTTP_QUERY", "source_node": "…121",
             "path": [], "transform_property": None,
             # a DIRECT attacker source with no transform: deterministically the
             # attacker controls raw nesting depth -> unsafe for this DoS mechanism
             "status": "DETERMINISTIC_UNSAFE", "established_by": "STATIC_ANALYSIS"},
        ],
        "version": 0, "llm_queries": 0,
    }


def required_unknowns(state):
    return [a["id"] for a in state["alternatives"] if a["status"] == "UNKNOWN"]


def coverage(state):
    # per-alternative: OPEN if ANY alternative is still UNKNOWN
    return "SEMANTICALLY_OPEN" if required_unknowns(state) else "SEMANTICALLY_CLOSED"


def adjudicate(state):
    if coverage(state) == "SEMANTICALLY_OPEN":
        return {"verdict": "NEEDS_SEMANTIC_REVIEW", "required_unknowns": required_unknowns(state)}
    # CLOSED: candidate is cleared ONLY IF every alternative is safe
    unsafe = [a["id"] for a in state["alternatives"]
              if a["status"] in ("DETERMINISTIC_UNSAFE", "RESOLVED_UNSAFE")]
    if unsafe:
        return {"verdict": "CANDIDATE_REAL",
                "reason": f"alternative(s) {unsafe} unsafe; a safe alternative does not clear the candidate"}
    return {"verdict": "CLEARED_SAFE", "reason": "every established alternative resolved safe"}


def fold(state, alt_id, protective, subject):
    """Inject a typed resolution for ONE alternative. Never touches another
    alternative, even if it shares a transform name."""
    ns = copy.deepcopy(state)
    for a in ns["alternatives"]:
        if a["id"] == alt_id:
            assert a["path"] and a["path"][-1] == subject, "resolution targets this branch's transform only"
            a["status"] = "RESOLVED_SAFE" if protective else "RESOLVED_UNSAFE"
            a["established_by"] = "SEMANTIC_REVIEW"
            a["resolved_property"] = f"{subject}.bounds_depth={protective}"
    ns["version"] += 1
    return ns


def show(state, label):
    v = adjudicate(state)
    alts = "  ".join(f"{a['id']}({a['origin_family']}:{a['status']}"
                     + (f"/{a['established_by']}" if a['established_by'] else "") + ")"
                     for a in state["alternatives"])
    print(f"  {label}: v{state['version']} coverage={coverage(state)} verdict={v['verdict']}"
          + (f" — {v.get('reason')}" if v.get('reason') else "")
          + (f" required={v.get('required_unknowns')}" if v.get('required_unknowns') else ""))
    print(f"       alternatives: {alts}")


print("=" * 78)
print("Per-alternative semantic closure (control #6)")
print("=" * 78)
s0 = initial_state()
show(s0, "v0 (before review)")
print("  NOTE: B is already deterministically unsafe (direct query, no bounding transform).")
print("        A's sanitizerX property is UNKNOWN -> SEMANTICALLY_OPEN on A.\n")

# resolve ONLY branch A: sanitizerX provides protection = TRUE
s0["llm_queries"] += 1
s1 = fold(s0, "A", protective=True, subject="sanitizerX")
show(s1, "v1 (sanitizerX resolved protective=TRUE on branch A)")
print("  => KEY: branch A is now cleared, but the candidate is NOT cleared —")
print("     branch B (HTTP_QUERY direct) remains unsafe. Resolution of A was NOT")
print("     applied to B. Verdict stays CANDIDATE_REAL.\n")

print("-" * 78)
print("Contrast: if branch B were instead query->wrapperY and BOTH resolve safe")
print("-" * 78)
s = initial_state()
s["alternatives"][1] = {"id": "B", "origin_family": "HTTP_QUERY", "source_node": "…121",
                        "path": ["wrapperY"], "transform_property": "bounds_depth",
                        "status": "UNKNOWN", "established_by": None}
show(s, "v0")
s["llm_queries"] += 1
s = fold(s, "A", protective=True, subject="sanitizerX")
show(s, "v1 (A safe)")
print("       still OPEN on B — A's resolution did not leak to B")
s["llm_queries"] += 1
s = fold(s, "B", protective=True, subject="wrapperY")
show(s, "v2 (B safe)")
print("  => only now, with EVERY alternative resolved safe, is the candidate CLEARED_SAFE.")
print(f"\n  established_by per alternative preserved: "
      + ", ".join(f"{a['id']}={a['established_by']}" for a in s["alternatives"]))
