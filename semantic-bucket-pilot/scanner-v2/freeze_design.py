#!/usr/bin/env python3
"""Pin the frozen study design: hash every canonical artifact + spec into one
manifest, so "the design remains frozen" is verifiable. Run to (re)generate
study/DESIGN_FROZEN.json; compare hashes later to prove nothing drifted.

This is a freeze record, NOT a redesign. It changes no scoring or labeling logic.
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

CANON = [
    # scoring
    "scoring_harness.py", "SCORING_PLAN.md", "freeze_scoring.py",
    # stage-0 corpus + build/verify machinery
    "build_family_manifest.py", "reconcile_manifest.py", "build_labeling_packet.py",
    "verify_prompt_tokens.py", "mde_simulation.py",
    # stage-1 specs
    "STAGE1_LABELING.md", "REFERENCE_PACKET.md", "UNSUPPORTED_ASSUMPTION_RUBRIC.md",
    "PROMPT_CONDITIONS.md", "STUDY_SCOPE.md", "STUDY_STAGE0.md",
    "ACCURACY_STUDY_PROTOCOL.md", "PACKET_RECONCILIATION.md",
    # frozen data artifacts
    "study/study_manifest.jsonl", "study/instances.jsonl", "study/families.json",
    "study/split.json", "study/FROZEN.json", "study/stage1_labeling_packet.jsonl",
    "study/reference_packet_FROZEN.json", "study/prompts_FROZEN.json",
    "study/mde_simulation.json",
    "study/scoring_freeze/FROZEN.json", "study/scoring_freeze/expected_report.json",
]


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main():
    hashes = {}
    missing = []
    for rel in CANON:
        p = os.path.join(HERE, rel)
        if os.path.exists(p):
            hashes[rel] = sha(p)
        else:
            missing.append(rel)
    combined = hashlib.sha256(
        "\n".join(f"{k}={hashes[k]}" for k in sorted(hashes)).encode()).hexdigest()
    rec = {
        "note": ("Frozen study design fingerprint. The design is closed; only a "
                 "genuine Stage-1 packet or labeling defect justifies a change. "
                 "Re-run freeze_design.py and diff to detect drift."),
        "stage1_started": False,
        "artifact_sha256": hashes,
        "missing_at_freeze": missing,
        "combined_fingerprint": combined,
    }
    with open(os.path.join(HERE, "study", "DESIGN_FROZEN.json"), "w") as fh:
        json.dump(rec, fh, indent=2, sort_keys=True)
    print(f"pinned {len(hashes)} artifacts; missing {len(missing)}")
    print("combined design fingerprint:", combined)
    if missing:
        print("MISSING:", missing)


if __name__ == "__main__":
    main()
