#!/usr/bin/env python3
"""Guard-fallthrough -> CanonicalEvidenceSet (control-flow security semantics).

Proves the canonical interface carries a CONTROL-FLOW question, not just value flow.
Value-flow fields (source/propagation/input_origin/sanitizer) are NOT_APPLICABLE
(per R1 tri-state: NOT_APPLICABLE is not a gap). The security question is framed on
the control-flow property:
    "Does failure of guard G prevent execution of sensitive operation S on every
     relevant path?"

Maps ONLY facts the detector/provenance layer establishes:
  terminator_profile + guard_calls  -> failure_disposition
  guard_cfg (condition shape, dominance-guarded, node ids) -> control-flow structure
  sink_sites -> sensitive operation identity

The boolean detector collapses C4/C5/C7 to SAFE; this adapter preserves the
control-flow uncertainty the boolean discards and routes them to review.
"""
import collections, json, sys
from pathlib import Path

RAW = Path(sys.argv[1] if len(sys.argv) > 1 else "gc-out/raw")


def rows(name, n):
    p = RAW / name
    return [ln.split("\t") for ln in p.read_text().splitlines() if ln.strip() and len(ln.split("\t")) == n] if p.exists() else []


# failure disposition from the existing verdict (terminator + bare/returned)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_fallthrough_verdict import derive as guard_derive  # noqa: E402
verdict_by_method = {}
for f in guard_derive(RAW).get("findings", []):
    verdict_by_method[f.get("method") or f.get("file", "")] = f

# guard_cfg: per method, guards (compound) and sinks (guarded)
guards = collections.defaultdict(list)
sinks = collections.defaultdict(list)
for r in rows("guard_cfg.tsv", 7):
    method, kind, node, line, compound, branch, cond = r
    key = method.split(":")[-1]
    if kind == "GUARD":
        guards[key].append({"node": node, "line": line, "compound": compound == "true", "cond": cond})
    else:
        sinks[key].append({"node": node, "line": line, "guarded": compound == "true"})  # col5 reused as guarded for SINK


DISPOSITION = {
    "SAFE_RETURNED": ("RETURNS_HALTS", "ESTABLISHED"),
    "SAFE_ALWAYS_TERMINATES": ("TERMINATES", "ESTABLISHED"),
    "CANDIDATE_GUARD_FALLTHROUGH": ("FALLTHROUGH_POSSIBLE", "ESTABLISHED"),
    "ABSTAIN_CALLEE_UNRESOLVED": ("UNKNOWN", "UNKNOWN"),
    "BARE_CONDITIONAL_NO_SINK_AFTER": ("NO_SINK_AFTER", "ESTABLISHED"),
    "SAFE_CALLEE_NOT_A_TERMINATOR": ("NOT_A_TERMINATOR", "ESTABLISHED"),
}
NA = {"status": "NOT_APPLICABLE", "reason": "guard-fallthrough is a control-flow question; attacker value-flow is not required"}


def build(method):
    gs = guards.get(method, [])
    ss = sinks.get(method, [])
    # failure disposition: find the verdict for this method
    vf = None
    for k, f in verdict_by_method.items():
        if (k or "").split(":")[-1] == method or method in (f.get("file", "")):
            vf = f; break
    raw_verdict = (vf or {}).get("verdict", "UNKNOWN")
    disp, disp_status = DISPOSITION.get(raw_verdict, ("UNKNOWN", "UNKNOWN"))

    compound = any(g["compound"] for g in gs)
    unguarded = [s for s in ss if not s["guarded"]]
    guarded = [s for s in ss if s["guarded"]]

    # ---- STRUCTURAL (control-flow) ----
    structural = {
        "sensitive_operation": [{"kind": "DB_WRITE", "node": s["node"], "line": s["line"]} for s in ss],
        "guard_identity": [{"node": g["node"], "line": g["line"], "condition": g["cond"],
                            "provenance": "guard_calls + guard_cfg"} for g in gs],
        "guard_dominates_sink": {s["node"]: s["guarded"] for s in ss},   # CFG dominance
        "guard_condition_shape": "COMPOUND" if compound else "SIMPLE",
        # value-flow structural fields explicitly NOT_APPLICABLE
        "source_location": NA, "propagation": NA, "sink_value_family": NA,
    }
    # ---- SEMANTIC ----
    semantic = {
        "failure_disposition": {"status": disp_status, "value": disp,
                                "provenance": "terminator_profile + guard_calls (bare/returned)"},
        "guard_path_coverage": None,   # filled below
        "authorization_property": {"status": "UNKNOWN",
                                   "note": "detector does not establish that the dominating guard checks the "
                                           "authorization S requires (no security heuristic added)"},
        # value-flow semantic fields NOT_APPLICABLE
        "input_origin": NA, "transform_semantics": NA, "sanitizer_property": NA,
    }
    # guard_path_coverage
    if unguarded:
        semantic["guard_path_coverage"] = {"status": "INCOMPLETE",
            "value": "an alternative path reaches a sensitive op with NO dominating guard",
            "unguarded_sinks": [s["node"] for s in unguarded], "provenance": "guard_cfg CFG dominance"}
    elif compound:
        semantic["guard_path_coverage"] = {"status": "MAY",
            "value": "guard condition is compound; coverage on every path not established",
            "provenance": "guard_cfg condition shape"}
    else:
        semantic["guard_path_coverage"] = {"status": "ESTABLISHED",
            "value": "a guard condition dominates every sensitive op", "provenance": "guard_cfg CFG dominance"}

    # ---- UNCERTAINTY + verdict/triage ----
    questions = []
    if disp == "FALLTHROUGH_POSSIBLE":
        verdict = "CANDIDATE_GUARD_FALLTHROUGH"
        coverage = "SEMANTICALLY_CLOSED"
        reason = "guard failure can fall through (conditional terminator, bare call) to the sensitive op"
    elif disp == "UNKNOWN":
        verdict = "NEEDS_SEMANTIC_REVIEW"
        coverage = "SEMANTICALLY_OPEN"
        questions.append(f"Does the guard helper terminate on failure (its terminator semantics are unresolved)? "
                         f"If it can return, guard failure would fall through to the sensitive operation.")
        reason = "guard helper terminator semantics unresolved"
    elif semantic["guard_path_coverage"]["status"] == "INCOMPLETE":
        verdict = "CANDIDATE_UNGUARDED_ALTERNATIVE"
        coverage = "SEMANTICALLY_CLOSED"   # structurally established that a path is unguarded
        reason = "an alternative execution path reaches a sensitive op with no dominating guard"
    elif semantic["guard_path_coverage"]["status"] == "MAY":
        verdict = "NEEDS_SEMANTIC_REVIEW"
        coverage = "SEMANTICALLY_OPEN"
        questions.append("Does guard G fire before sensitive operation S on every relevant path? "
                         "The guard condition is compound, so a path may bypass it.")
        reason = "compound guard condition; per-path coverage not established"
    else:
        verdict = "CLASS_SAFE_FALLTHROUGH"
        coverage = "SEMANTICALLY_CLOSED"
        reason = "guard failure terminates/returns before S, and a guard dominates every sensitive op"
        # authorization remains a separate open dimension (not a fallthrough finding)
        questions.append("(separate dimension) Does the dominating guard condition establish the "
                         "authorization the sensitive operation requires?")

    return {
        "meta": {"finding_id": method, "vuln_class": "GUARD_FALLTHROUGH", "language": "js"},
        "structural_evidence": structural,
        "semantic_evidence": semantic,
        "uncertainty": {"coverage_state": coverage, "semantic_questions": questions,
                        "reason": reason},
        "verdict": verdict,
    }


if __name__ == "__main__":
    methods = sorted(set(list(guards) + list(sinks)) - {"program", ""})
    for m in methods:
        ev = build(m)
        s = ev["semantic_evidence"]
        print(f"[{m}] verdict={ev['verdict']}  coverage={ev['uncertainty']['coverage_state']}")
        print(f"     failure_disposition={s['failure_disposition']['value']}({s['failure_disposition']['status']})"
              f"  condition_shape={ev['structural_evidence']['guard_condition_shape']}"
              f"  guard_path_coverage={s['guard_path_coverage']['status']}")
        print(f"     value-flow fields: source={s['input_origin']['status']} "
              f"propagation={ev['structural_evidence']['propagation']['status']} "
              f"sanitizer={s['sanitizer_property']['status']}")
        if ev["uncertainty"]["semantic_questions"]:
            print(f"     Q: {ev['uncertainty']['semantic_questions'][0]}")
        print()
