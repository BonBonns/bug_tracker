#!/usr/bin/env python3
"""Scoring rubric for the semantic-bucket pilot (A/B/C design).

Conditions:
  A = code + highlighted operation
  B = A + established facts + generic "unresolved" status
  C = B + typed uncertainty category + focused question

PRIMARY comparison is B vs C (does typed bucketing + a focused question beat a
generic UNKNOWN, holding code/candidate/facts constant?). A is the general
baseline. Only cases whose scanner_state.candidate_present is true AND routable
belong here; non-routable / no-candidate cases live in routing_eval.json, not
in this accuracy comparison.

Scored against `verified_ground_truth` (the independently established final
answer), which is a SEPARATE field from scanner_state (the scanner's own
uncertainty). A case can have scanner_state = relationship_unresolved and
verified_ground_truth = safe (e.g. SB-07) — the reviewer's job is to reach the
verified answer; the scanner's uncertainty is the starting point, not the key.

Dimensions (per the design):
  1. correct_conclusion        response.conclusion == verified.conclusion
  2. correct_relationship      response.relationship_answer == verified.relationship_answer
  3. appropriate_abstention    only when verified.conclusion == "unresolved":
                               did the response also abstain rather than guess?
  4. unsupported_assumption    HEURISTIC keyword flag (NOT fully automatable —
                               triage signal for a human scorer, never the final
                               word); flags a response that reached a wrong
                               confident conclusion by echoing a known trap
                               without naming it in its own unsupported_assumptions.
  5. contradicts_deterministic did the response assert a confident safe/vulnerable
                               verdict while the deterministic layer marked the
                               relationship UNRESOLVED, without engaging that
                               uncertainty? (informational; being confidently
                               RIGHT, as in SB-07 -> safe, is not a contradiction)
  6. evidence_overlap          informational keyword overlap with verified evidence.

NOTE: dimensions 4 and 6 use crude keyword heuristics because no
semantic-similarity model is available here. They are triage signals for a
human scorer, not certified automatic scores. The dry run's whole purpose is to
check whether this rubric is usable before it is trusted at scale.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
RUNS = ROOT / "runs"
CONDITIONS = ("A", "B", "C")


def load_case(case_id):
    return json.loads((CORPUS / f"{case_id}.json").read_text())


def verified(case):
    return case.get("verified_ground_truth") or case.get("ground_truth")


def _norm(s):
    return (s or "").strip().lower()


def _keyword_hit(needle, haystack_list):
    needle_words = set(re.findall(r"[a-z0-9_]{4,}", _norm(needle)))
    if not needle_words:
        return False
    for h in haystack_list or []:
        if len(needle_words & set(re.findall(r"[a-z0-9_]{4,}", _norm(h)))) >= 2:
            return True
    return False


def score_response(case_id, condition, response):
    case = load_case(case_id)
    v = verified(case)
    scanner_unresolved = (case.get("scanner_state", {}) or {}).get(
        "assigned_uncertainty_category") == "relationship_unresolved"

    r = {
        "case_id": case_id, "condition": condition, "role": case.get("role"),
        "scanner_category": (case.get("scanner_state", {}) or {}).get("assigned_uncertainty_category"),
        "verified_conclusion": _norm(v["conclusion"]),
        "correct_conclusion": _norm(response.get("conclusion")) == _norm(v["conclusion"]),
        "correct_relationship": _norm(response.get("relationship_answer")) == _norm(v["relationship_answer"]),
        "appropriate_abstention": None,
        "unsupported_assumption_flag": False,
        "contradicts_deterministic": None,
        "evidence_overlap_fraction": None,
        "notes": [],
    }

    if _norm(v["conclusion"]) == "unresolved":
        r["appropriate_abstention"] = _norm(response.get("conclusion")) == "unresolved"

    traps = (v.get("unsupported_assumptions_that_must_not_be_made")
             or v.get("unsupported_assumptions_that_must_not_be_used_to_dismiss_this") or [])
    if traps and _norm(response.get("conclusion")) != _norm(v["conclusion"]) \
            and _norm(response.get("conclusion")) in ("safe", "vulnerable"):
        named = response.get("unsupported_assumptions") or []
        for trap in traps:
            if _keyword_hit(trap, response.get("evidence_used") or []) and not _keyword_hit(trap, named):
                r["unsupported_assumption_flag"] = True
                break
        else:
            r["unsupported_assumption_flag"] = "REVIEW"
            r["notes"].append("wrong confident conclusion; no known trap matched by heuristic — human review")

    if scanner_unresolved:
        # A confident safe/vulnerable that matches the verified answer is fine.
        # A confident verdict that does NOT match, on a scanner-unresolved case,
        # is a contradiction of the deterministic uncertainty worth flagging.
        r["contradicts_deterministic"] = (
            _norm(response.get("conclusion")) in ("safe", "vulnerable")
            and _norm(response.get("conclusion")) != _norm(v["conclusion"])
        )

    gt_ev = v.get("evidence_used") or []
    if gt_ev:
        hits = sum(1 for e in gt_ev if _keyword_hit(e, response.get("evidence_used") or []))
        r["evidence_overlap_fraction"] = round(hits / len(gt_ev), 2)
    return r


def score_all_runs():
    results = []
    for run_file in sorted(RUNS.glob("*.json")):
        run = json.loads(run_file.read_text())
        if run.get("condition") not in CONDITIONS:
            continue
        try:
            resp = json.loads(run["response_text"])
        except (KeyError, json.JSONDecodeError) as e:
            results.append({"case_id": run.get("case_id"), "condition": run.get("condition"),
                            "trial": run.get("trial"), "PARSE_ERROR": str(e), "run_file": run_file.name})
            continue
        s = score_response(run["case_id"], run["condition"], resp)
        s["trial"] = run.get("trial"); s["run_file"] = run_file.name
        results.append(s)
    return results


def summarize(results):
    from collections import defaultdict
    by_cond = defaultdict(list)
    for r in results:
        if "PARSE_ERROR" in r:
            continue
        by_cond[r["condition"]].append(r)
    out = {}
    for cond in CONDITIONS:
        rs = by_cond.get(cond, [])
        n = len(rs)
        if not n:
            continue
        out[cond] = {
            "n": n,
            "conclusion_accuracy": round(sum(x["correct_conclusion"] for x in rs) / n, 2),
            "relationship_accuracy": round(sum(x["correct_relationship"] for x in rs) / n, 2),
            "abstention_correct": _rate([x["appropriate_abstention"] for x in rs]),
            "unsupported_assumption_flags": sum(1 for x in rs if x["unsupported_assumption_flag"] is True),
            "contradicts_deterministic": sum(1 for x in rs if x["contradicts_deterministic"] is True),
        }
    if "B" in out and "C" in out:
        out["PRIMARY_B_vs_C"] = {
            "conclusion_accuracy_delta": round(out["C"]["conclusion_accuracy"] - out["B"]["conclusion_accuracy"], 2),
            "relationship_accuracy_delta": round(out["C"]["relationship_accuracy"] - out["B"]["relationship_accuracy"], 2),
            "note": "positive delta = bucket-guided review (C) beats generic-unknown (B), the load-bearing result",
        }
    return out


def _rate(vals):
    scored = [v for v in vals if v is not None]
    return round(sum(1 for v in scored if v) / len(scored), 2) if scored else None


if __name__ == "__main__":
    res = score_all_runs()
    print(json.dumps({"results": res, "summary": summarize(res)}, indent=2))
