#!/usr/bin/env python3
"""Produce the disagreement file for the frozen tie-break reviewer, from two
validated Stage-1 label files. Flags every instance where the two reviewers differ
on a consequential field, with both answers + rationale so the adjudicator can
resolve it. Run only AFTER validate_stage1_import.py passes.

Usage: build_disagreement_file.py reviewer_1_labels.jsonl reviewer_2_labels.jsonl
Writes study/review/disagreements.jsonl and prints an agreement summary.
"""
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "study", "review")
FIELDS = ["evidence_reference_conclusion",   # primary scored field
          "established_facts_valid",          # gates invalid-packet exclusion
          "program_outcome",                  # reported separately
          "relationship_answer"]


def load(path):
    d = {}
    for l in open(path):
        r = json.loads(l)
        iid = r.get("instance_id") or r.get("case", {}).get("instance_id")
        d[iid] = {"reviewer_id": r.get("reviewer_id"), **r.get("label", r)}
    return d


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: build_disagreement_file.py reviewer_1_labels.jsonl reviewer_2_labels.jsonl")
    r1, r2 = load(sys.argv[1]), load(sys.argv[2])
    both = sorted(set(r1) & set(r2))
    agree = Counter()
    disagreements = []
    for i in both:
        diffs = [f for f in FIELDS if r1[i].get(f) != r2[i].get(f)]
        for f in FIELDS:
            agree[f] += (r1[i].get(f) == r2[i].get(f))
        if diffs:
            disagreements.append({
                "instance_id": i, "fields_in_disagreement": diffs,
                "reviewer_1": {f: r1[i].get(f) for f in FIELDS + ["rationale"]},
                "reviewer_2": {f: r2[i].get(f) for f in FIELDS + ["rationale"]},
                "tiebreak": {f: None for f in FIELDS},   # adjudicator fills
                "tiebreak_reviewer_id": None, "tiebreak_rationale": None,
            })
    path = os.path.join(OUT, "disagreements.jsonl")
    with open(path, "w") as fh:
        for d in disagreements:
            fh.write(json.dumps(d, sort_keys=True) + "\n")

    n = len(both)
    print(f"instances compared: {n}")
    for f in FIELDS:
        print(f"  {f:30} agreement {agree[f]}/{n} ({agree[f]/n:.1%})")
    print(f"disagreements to adjudicate: {len(disagreements)} -> {path}")
    print("The tie-break reviewer fills `tiebreak.*` per the frozen procedure; the "
          "adjudicated values become the final stage1_labels.jsonl (then hashed).")


if __name__ == "__main__":
    main()
