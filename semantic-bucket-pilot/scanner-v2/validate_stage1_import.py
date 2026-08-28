#!/usr/bin/env python3
"""Validate the two completed Stage-1 reviewer label files: confirm both reviewers
labeled ALL 438 instance IDs, independently, with schema-valid values. Then (via
build_disagreement_file.py) a disagreement file is produced for the tie-break.

Usage: validate_stage1_import.py reviewer_1_labels.jsonl reviewer_2_labels.jsonl
Exits non-zero on any coverage/schema/independence violation.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACKET = os.path.join(HERE, "study", "stage1_labeling_packet.jsonl")

ENUM = {
    "evidence_reference_conclusion": {"safe", "vulnerable", "unresolved"},
    "established_facts_valid": {"valid", "invalid", "unresolved"},
    "program_outcome": {"safe", "vulnerable", "not_established"},
    "relationship_answer": {"established", "contradicted", "unresolved"},
    "reviewer_confidence": {"high", "medium", "low"},
}
REQUIRED_TEXT = ["rationale", "supporting_evidence"]


def load_labels(path):
    rows = {}
    for l in open(path):
        r = json.loads(l)
        iid = r.get("instance_id") or r.get("case", {}).get("instance_id")
        lab = r.get("label", r)
        rows[iid] = {"reviewer_id": r.get("reviewer_id"), **lab}
    return rows


def check(name, rows, expected_ids, errs):
    ids = set(rows)
    missing = expected_ids - ids
    extra = ids - expected_ids
    if missing:
        errs.append(f"{name}: MISSING {len(missing)} ids (e.g. {sorted(missing)[:3]})")
    if extra:
        errs.append(f"{name}: EXTRA {len(extra)} ids (e.g. {sorted(extra)[:3]})")
    if len(rows) != len(expected_ids):
        errs.append(f"{name}: covered {len(rows)} != {len(expected_ids)} expected")
    bad = 0
    for iid, lab in rows.items():
        for f, allowed in ENUM.items():
            if lab.get(f) not in allowed:
                bad += 1
                if bad <= 3:
                    errs.append(f"{name}:{iid}: {f}={lab.get(f)!r} not in {sorted(allowed)}")
        for f in REQUIRED_TEXT:
            if not (lab.get(f) and str(lab.get(f)).strip()):
                bad += 1
                if bad <= 3:
                    errs.append(f"{name}:{iid}: empty required field {f}")
    if bad > 3:
        errs.append(f"{name}: ...and {bad - 3} more schema violations")
    return errs


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: validate_stage1_import.py reviewer_1_labels.jsonl reviewer_2_labels.jsonl")
    expected = {json.loads(l)["packet_instance_id"] for l in open(PACKET)}
    r1 = load_labels(sys.argv[1])
    r2 = load_labels(sys.argv[2])
    errs = []
    check("reviewer_1", r1, expected, errs)
    check("reviewer_2", r2, expected, errs)

    id1 = {lab.get("reviewer_id") for lab in r1.values()}
    id2 = {lab.get("reviewer_id") for lab in r2.values()}
    if id1 & id2:
        errs.append(f"independence: both files share reviewer_id {id1 & id2}")
    # heuristic independence flag: identical rationale strings across the two files
    shared = sum(1 for i in (set(r1) & set(r2))
                 if r1[i].get("rationale") and r1[i]["rationale"] == r2[i].get("rationale"))
    if shared > 0.10 * len(expected):
        errs.append(f"independence WARNING: {shared} identical rationales "
                    f"({shared/len(expected):.0%}) — possible non-independent review")

    # agreement summary (informational)
    both = set(r1) & set(r2)
    agree_primary = sum(1 for i in both
                        if r1[i].get("evidence_reference_conclusion")
                        == r2[i].get("evidence_reference_conclusion"))
    print(f"reviewer_1: {len(r1)} labeled   reviewer_2: {len(r2)} labeled   expected {len(expected)}")
    print(f"primary-field agreement: {agree_primary}/{len(both)} "
          f"({agree_primary/len(both):.1%})" if both else "no overlap")
    if errs:
        print("\nVALIDATION FAILED:")
        for e in errs:
            print("  -", e)
        sys.exit(1)
    print("\nVALIDATION PASSED: both reviewers labeled all 438 ids independently, schema valid.")
    print("Next: build_disagreement_file.py for the frozen tie-break reviewer.")


if __name__ == "__main__":
    main()
