#!/usr/bin/env python3
"""Score the mechanics dry run (DEVELOPMENT-ONLY).

Reads the blinded reviewer responses (archive/responses/*.json), unblinds them
via archive/blind_key.json, and validates the SCORING + PARSING machinery. This
is a mechanics test: it checks that the pipeline parses, unblinds, aligns, and
scores end-to-end. It does NOT produce an accuracy claim -- these five cases are
development-only and are excluded from any confirmatory statistic.

Scoring maps the reviewer's classification against the hand-verified ground
truth per case:
  - safe / vulnerable are the decisive labels.
  - unknown is an ABSTENTION: for a case whose ground truth is itself
    'unresolved', unknown is the correct answer; otherwise unknown is scored as
    a non-commitment (neither correct nor a false decision), tracked separately.

Output: archive/dev_scores.json and a printed per-condition summary.
"""
import json
import os
import re
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ARCH = os.path.join(HERE, "archive")


def parse_response(path):
    """Robustly parse a reviewer JSON response; tolerate stray prose/code fences."""
    raw = open(path).read()
    # try direct
    try:
        return json.loads(raw), None
    except Exception:
        pass
    # extract the first {...} block
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0)), None
        except Exception as e:
            return None, f"json-in-block failed: {e}"
    return None, "no json object found"


def score_one(classification, ground_truth):
    c = (classification or "").strip().lower()
    gt = ground_truth.strip().lower()
    if c not in ("safe", "vulnerable", "unknown"):
        return "invalid_label"
    if gt == "unresolved":
        return "correct" if c == "unknown" else ("committed_wrong" if c in ("safe", "vulnerable") else "abstain")
    # gt is safe or vulnerable
    if c == gt:
        return "correct"
    if c == "unknown":
        return "abstain"
    return "committed_wrong"


def main():
    key = json.load(open(os.path.join(ARCH, "blind_key.json")))
    resp_dir = os.path.join(ARCH, "responses")

    rows = []
    missing = []
    for bid, meta in key.items():
        path = os.path.join(resp_dir, bid + ".json")
        if not os.path.exists(path):
            missing.append(bid)
            continue
        obj, err = parse_response(path)
        classification = (obj or {}).get("classification") if obj else None
        outcome = score_one(classification, meta["ground_truth"]) if obj else "parse_error"
        rows.append({
            "blind_id": bid, "case": meta["case"], "condition": meta["condition"],
            "ground_truth": meta["ground_truth"],
            "classification": classification, "outcome": outcome,
            "parse_error": err,
        })

    # per-condition mechanics summary
    by_cond = defaultdict(lambda: defaultdict(int))
    for r in rows:
        by_cond[r["condition"]][r["outcome"]] += 1

    report = {
        "development_only": True,
        "note": ("Mechanics validation only. Five development cases; NOT an "
                 "accuracy result and excluded from all confirmatory statistics."),
        "n_responses": len(rows), "n_missing": len(missing),
        "missing_blind_ids": missing,
        "parse_ok": sum(1 for r in rows if r["outcome"] != "parse_error"),
        "by_condition": {c: dict(d) for c, d in by_cond.items()},
        "rows": sorted(rows, key=lambda r: (r["case"], r["condition"])),
    }
    with open(os.path.join(ARCH, "dev_scores.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)

    print(f"responses parsed : {report['parse_ok']}/{len(rows)}"
          + (f"  MISSING {len(missing)}" if missing else ""))
    print("per-condition outcome tallies (mechanics only, NOT accuracy):")
    for cond in ("A", "B", "C"):
        print(f"  {cond}: {dict(by_cond[cond])}")
    print("\nper-case x condition:")
    for r in report["rows"]:
        pe = "  <PARSE_ERR>" if r["outcome"] in ("parse_error", "invalid_label") else ""
        print(f"  {r['case']:20} {r['condition']}  gt={r['ground_truth']:11} "
              f"-> {str(r['classification']):11} [{r['outcome']}]{pe}")


if __name__ == "__main__":
    main()
