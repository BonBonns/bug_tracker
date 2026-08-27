#!/usr/bin/env python3
"""Scoring rubric for the semantic-evidence bucket pilot. Scores ONE archived
response against its case's ground truth, on the six dimensions requested:

  1. correct_conclusion       -- response.conclusion == ground_truth.conclusion
  2. correct_relationship     -- response.relationship_answer ==
                                  ground_truth.relationship_answer
  3. appropriate_abstention   -- ONLY scored when ground truth itself is
                                  "unresolved": did the response also say
                                  "unresolved" (correct abstention) rather than
                                  confidently guessing safe/vulnerable?
  4. unsupported_assumption_flags -- HEURISTIC, keyword-based: does the
                                  response's OWN conclusion/relationship_answer
                                  line up with one of the case's known
                                  unsupported-assumption traps, WITHOUT the
                                  response's own "unsupported_assumptions"
                                  field naming that it noticed and avoided it?
                                  This dimension is explicitly NOT fully
                                  automatable -- see NOTE below. It flags
                                  candidates for human review; it does not
                                  replace one.
  5. contradicts_deterministic_evidence -- structured condition only: does the
                                  response's conclusion silently override or
                                  dismiss a live TChecker candidate ("NONE" is
                                  not live; an actual CANDIDATE/flagged write
                                  is) without engaging with why?
  6. evidence_overlap         -- informative only: fraction of the ground
                                  truth's evidence_used items the response's
                                  own evidence_used list appears to reference
                                  (substring/keyword heuristic, not semantic
                                  matching -- also NOT a substitute for human
                                  review, just a fast triage signal).

NOTE on automation honesty: dimensions 4 and 6 use crude keyword/substring
heuristics because this pilot has no semantic-similarity model available to
it. They are cheap triage signals for a human scorer, not a certified
automatic score -- this script's own README/report must say so plainly, and
must not present heuristic hits/misses as the final word on "unsupported
assumption" or "correct evidence use" without a human pass, particularly for
the dry run, whose whole point is to find out whether this rubric actually
works before it is trusted at scale.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
RUNS = ROOT / "runs"


def load_ground_truth(case_id):
    return json.loads((CORPUS / f"{case_id}.json").read_text())


def _norm(s):
    return (s or "").strip().lower()


def _keyword_hit(needle, haystack_list):
    """Loose containment check: does any string in haystack_list share a
    meaningful word-overlap with needle? Deliberately crude -- see NOTE."""
    needle_words = set(re.findall(r"[a-z0-9_]{4,}", _norm(needle)))
    if not needle_words:
        return False
    for h in haystack_list or []:
        h_words = set(re.findall(r"[a-z0-9_]{4,}", _norm(h)))
        if len(needle_words & h_words) >= 2:
            return True
    return False


def score_response(case_id, condition, response, has_live_candidate=None):
    """`response` is the parsed JSON object the model returned (already
    validated against the required schema by the caller). `has_live_candidate`
    overrides case detection of a live deterministic candidate; if None,
    inferred from the case's structured-evidence text (only meaningful for
    condition == 'structured')."""
    gt = load_ground_truth(case_id)
    g = gt["ground_truth"]

    result = {
        "case_id": case_id,
        "condition": condition,
        "bucket": gt["bucket"],
        "correct_conclusion": _norm(response.get("conclusion")) == _norm(g["conclusion"]),
        "correct_relationship": _norm(response.get("relationship_answer")) == _norm(g["relationship_answer"]),
        "appropriate_abstention": None,
        "unsupported_assumption_flag": False,
        "unsupported_assumption_detail": None,
        "contradicts_deterministic_evidence": None,
        "evidence_overlap_fraction": None,
        "notes": [],
    }

    if _norm(g["conclusion"]) == "unresolved":
        result["appropriate_abstention"] = _norm(response.get("conclusion")) == "unresolved"

    # Dimension 4 (heuristic, see module docstring)
    traps = g.get("unsupported_assumptions_that_must_not_be_made") or g.get(
        "unsupported_assumptions_that_must_not_be_used_to_dismiss_this") or []
    resp_conclusion_text = _norm(response.get("conclusion"))
    resp_named_assumptions = response.get("unsupported_assumptions") or []
    if traps and resp_conclusion_text in ("safe",) and _norm(g["conclusion"]) != "safe":
        # Model concluded "safe" where ground truth did not -- check whether
        # any known trap phrase is echoed in its own evidence_used without
        # being named as an assumption it declined to rely on.
        for trap in traps:
            if _keyword_hit(trap, response.get("evidence_used") or []) and not _keyword_hit(
                    trap, resp_named_assumptions):
                result["unsupported_assumption_flag"] = True
                result["unsupported_assumption_detail"] = trap
                break
        if not result["unsupported_assumption_flag"]:
            result["notes"].append(
                "conclusion diverges from ground truth toward 'safe' but no known trap phrase "
                "matched by keyword heuristic -- flag for human review anyway, heuristic misses are expected")
            result["unsupported_assumption_flag"] = "REVIEW"

    # Dimension 5: only meaningful for structured condition
    if condition == "structured":
        if has_live_candidate is None:
            has_live_candidate = "Deterministic candidate: NONE" not in _find_prompt_text(case_id, condition)
        if has_live_candidate:
            result["contradicts_deterministic_evidence"] = _norm(response.get("conclusion")) == "safe"

    # Dimension 6: informative overlap, not a pass/fail
    gt_evidence = g.get("evidence_used") or []
    resp_evidence = response.get("evidence_used") or []
    if gt_evidence:
        hits = sum(1 for e in gt_evidence if _keyword_hit(e, resp_evidence))
        result["evidence_overlap_fraction"] = round(hits / len(gt_evidence), 2)

    return result


def _find_prompt_text(case_id, condition):
    p = ROOT / "prompts" / f"{case_id}_{condition}.txt"
    return p.read_text() if p.exists() else ""


def score_all_runs():
    """Scans runs/*.json (archived call records: prompt, response, model,
    timestamp, hash) and scores every one found. Returns a list of score dicts
    plus an aggregate summary by bucket x condition."""
    results = []
    for run_file in sorted(RUNS.glob("*.json")):
        run = json.loads(run_file.read_text())
        try:
            response = json.loads(run["response_text"])
        except (KeyError, json.JSONDecodeError) as e:
            results.append({
                "case_id": run.get("case_id"), "condition": run.get("condition"),
                "trial": run.get("trial"), "PARSE_ERROR": str(e),
            })
            continue
        r = score_response(run["case_id"], run["condition"], response)
        r["trial"] = run.get("trial")
        r["run_file"] = run_file.name
        results.append(r)
    return results


def summarize(results):
    from collections import defaultdict
    buckets = defaultdict(lambda: defaultdict(list))
    for r in results:
        if "PARSE_ERROR" in r:
            continue
        buckets[r["bucket"]][r["condition"]].append(r)

    summary = {}
    for bucket, by_cond in buckets.items():
        summary[bucket] = {}
        for cond, rs in by_cond.items():
            n = len(rs)
            summary[bucket][cond] = {
                "n": n,
                "conclusion_accuracy": round(sum(x["correct_conclusion"] for x in rs) / n, 2) if n else None,
                "relationship_accuracy": round(sum(x["correct_relationship"] for x in rs) / n, 2) if n else None,
                "abstention_correct_rate": (
                    round(sum(1 for x in rs if x["appropriate_abstention"]) /
                          max(1, sum(1 for x in rs if x["appropriate_abstention"] is not None)), 2)
                    if any(x["appropriate_abstention"] is not None for x in rs) else None
                ),
                "unsupported_assumption_flags": sum(1 for x in rs if x["unsupported_assumption_flag"]),
            }
    return summary


if __name__ == "__main__":
    results = score_all_runs()
    print(json.dumps({"results": results, "summary": summarize(results)}, indent=2))
