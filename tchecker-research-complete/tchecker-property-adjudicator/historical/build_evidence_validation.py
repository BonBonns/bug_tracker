#!/usr/bin/env python3
"""Validation-bypass -> CanonicalEvidenceSet (iteration / validation-effect semantics)."""
import collections, sys
from pathlib import Path
RAW = Path(sys.argv[1] if len(sys.argv) > 1 else "vb-out/raw")
def rows(name, n):
    p = RAW / name; out = []
    if p.exists():
        for ln in p.read_text().splitlines():
            f = ln.split("\t")
            if len(f) == n and f[0].strip(): out.append(f)
    return out
ctx = {}
for r in rows("loop_exits.tsv", 9):
    ctx[(r[0].split("/")[-1], r[4])] = {"records_error": r[6] == "true", "per_elem": r[7] == "true"}
_CTXFILE = True
KNOWN_CONTINUE = {"forEach", "map"}
KNOWN_SEARCH = {"every", "some", "find", "findIndex", "filter"}
NA = {"status": "NOT_APPLICABLE", "reason": "iteration/control-effect question; attacker value-flow not required"}
def control_effect(kind, scope, api, retv, rec_err, per_elem):
    if kind == "CONTINUE": return "CONTINUE_CURRENT", "ESTABLISHED"
    if kind == "BREAK": return "BREAK_LOOP", "ESTABLISHED"
    if scope == "CALLBACK":
        if api in KNOWN_CONTINUE: return "RETURN_CALLBACK", "ESTABLISHED"
        if api in KNOWN_SEARCH: return "SEARCH_SUCCESS", "ESTABLISHED"
        return "UNKNOWN", "UNKNOWN"
    if rec_err: return "FAILURE_ABORT", "ESTABLISHED"
    if retv: return "SEARCH_SUCCESS", "ESTABLISHED"
    if not per_elem: return "FAILURE_ABORT", "ESTABLISHED"
    return "RETURN_ENCLOSING", "ESTABLISHED"
VERDICT = {
    "CONTINUE_CURRENT": ("CLASS_SAFE_CONTINUE", "SEMANTICALLY_CLOSED"),
    "RETURN_CALLBACK": ("CLASS_SAFE_CALLBACK_RETURN", "SEMANTICALLY_CLOSED"),
    "SEARCH_SUCCESS": ("CLASS_SAFE_SEARCH_RESULT", "SEMANTICALLY_CLOSED"),
    "FAILURE_ABORT": ("CLASS_SAFE_REJECTS_SET", "SEMANTICALLY_CLOSED"),
    "RETURN_ENCLOSING": ("CANDIDATE_VALIDATION_BYPASS", "SEMANTICALLY_CLOSED"),
    "BREAK_LOOP": ("NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN"),
    "UNKNOWN": ("NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN"),
}
INVARIANT_Q = ("Does this control action permit relevant remaining elements to avoid required validation, "
               "or does it merely complete/reject the current validation operation safely?")
def build_method(method, exits):
    alts = []
    for e in exits:
        kind, node, line, scope, api, retv = e[2], e[3], e[4], e[5], e[6], e[7] == "true"
        fileleaf = e[0].split("::")[0].split("/")[-1]
        rc = ctx.get((fileleaf, line), {"records_error": False, "per_elem": True})
        eff, status = control_effect(kind, scope, api, retv, rc["records_error"], rc["per_elem"])
        verdict, coverage = VERDICT[eff]
        alts.append({"exit_node": node, "exit_line": line, "exit_kind": kind, "return_scope": scope,
                     "callback_api": api, "returns_value": retv, "effect": eff, "status": status,
                     "verdict": verdict, "coverage": coverage})
    unsafe = [a for a in alts if a["verdict"] == "CANDIDATE_VALIDATION_BYPASS"]
    open_ = [a for a in alts if a["coverage"] == "SEMANTICALLY_OPEN"]
    if unsafe: overall, coverage = "CANDIDATE_VALIDATION_BYPASS", "SEMANTICALLY_CLOSED"
    elif open_: overall, coverage = "NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN"
    else: overall, coverage = "CLASS_SAFE", "SEMANTICALLY_CLOSED"
    return {"method": method, "verdict": overall, "coverage": coverage, "alts": alts,
            "questions": [INVARIANT_Q] if coverage == "SEMANTICALLY_OPEN" else [],
            "value_flow": {"source": NA["status"], "propagation": NA["status"], "sanitizer": NA["status"]}}
if __name__ == "__main__":
    by_method = collections.defaultdict(list)
    for e in rows("loopctl.tsv", 9):
        leaf = e[0].split(":")[-1]
        if leaf == "program": continue
        by_method[leaf].append(e)
    for method in sorted(by_method):
        ev = build_method(method, by_method[method])
        print(f"[{method}] verdict={ev['verdict']}  coverage={ev['coverage']}")
        for a in ev["alts"]:
            print(f"     exit L{a['exit_line']} kind={a['exit_kind']} scope={a['return_scope']} api={a['callback_api']}"
                  f" retval={a['returns_value']} -> control_effect={a['effect']}({a['status']}) => {a['verdict']}")
        print(f"     value-flow: source={ev['value_flow']['source']} propagation={ev['value_flow']['propagation']} sanitizer={ev['value_flow']['sanitizer']}")
        if ev["questions"]: print(f"     Q: {ev['questions'][0]}")
        print()
