#!/usr/bin/env python3
"""Freeze the scoring harness against SYNTHETIC labels + SYNTHETIC A/B/C outputs.

Proves scoring_harness.py runs end-to-end and is deterministic BEFORE any real
label exists, then records sha256 of the harness, the plan, and the synthetic
inputs/outputs. Stage 2 runs the identical harness on real data. The synthetic
labels are fake and are clearly named as such — they exist only to lock the code.
"""
import hashlib
import json
import os
import random

import scoring_harness as H

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "study", "scoring_freeze")
SEED = 424242


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def synth_labels(instances, rng):
    """Family-clustered synthetic labels (FAKE). Pre-patch side biased toward
    VULNERABLE, post-patch toward SAFE, small UNRESOLVED fraction — only to exercise
    the harness, not a claim about the data."""
    fam_risk = {}
    rows = []
    for r in instances:
        fam = r["family_id"]
        if fam not in fam_risk:
            fam_risk[fam] = rng.random()          # latent site risk
        u = rng.random()
        if u < 0.08:
            lab = "UNRESOLVED"
        else:
            base = fam_risk[fam]
            pre = r["revision_side"] == "pre_patch"
            pv = base * (0.9 if pre else 0.25)     # pre-patch more likely vulnerable
            lab = "VULNERABLE" if rng.random() < pv else "SAFE"
        rows.append({"instance_id": r["instance_id"], "stage1_label": lab})
    return rows


def synth_predictions(labels, rng):
    """Three conditions; B deliberately more accurate + better-calibrated than A;
    C weakest. Includes abstentions and a few parse errors."""
    acc = {"A": 0.66, "B": 0.82, "C": 0.58}
    abst = {"A": 0.18, "B": 0.10, "C": 0.22}
    parse = {"A": 0.03, "B": 0.01, "C": 0.02}
    rows = []
    gt = {r["instance_id"]: r["stage1_label"] for r in labels}
    for cond in ("A", "B", "C"):
        for iid, g in gt.items():
            u = rng.random()
            if u < parse[cond]:
                p = "PARSE_ERROR"
            elif u < parse[cond] + abst[cond] + (0.25 if g == "UNRESOLVED" else 0):
                # abstain more on truly-unresolved, and B abstains a bit more there
                if g == "UNRESOLVED" and cond == "B" and rng.random() < 0.5:
                    p = "ABSTAIN"
                else:
                    p = "ABSTAIN"
            elif g == "UNRESOLVED":
                p = rng.choice(["VULNERABLE", "SAFE"])   # over-confident commit
            else:
                correct = rng.random() < acc[cond]
                p = g if correct else ("SAFE" if g == "VULNERABLE" else "VULNERABLE")
            rows.append({"instance_id": iid, "condition": cond, "prediction": p})
    return rows


def main():
    os.makedirs(OUT, exist_ok=True)
    instances = H.load_jsonl(os.path.join(HERE, "study", "instances.jsonl"))
    rng = random.Random(SEED)
    labels = synth_labels(instances, rng)
    preds = synth_predictions(labels, rng)

    lab_p = os.path.join(OUT, "synthetic_labels.jsonl")
    prd_p = os.path.join(OUT, "synthetic_predictions.jsonl")
    with open(lab_p, "w") as fh:
        for r in labels:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    with open(prd_p, "w") as fh:
        for r in preds:
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    rep1 = H.run(instances, labels, preds, "confirmatory")
    rep2 = H.run(instances, labels, preds, "confirmatory")   # determinism check
    assert json.dumps(rep1, sort_keys=True) == json.dumps(rep2, sort_keys=True), \
        "scoring harness is not deterministic"

    exp_p = os.path.join(OUT, "expected_report.json")
    with open(exp_p, "w") as fh:
        json.dump(rep1, fh, indent=2, sort_keys=True, default=str)

    # sanity: the harness must recover the built-in B>A synthetic effect
    prim = rep1["primary_comparison"]
    assert prim["point"] > 0, "synthetic B>A effect not recovered"
    assert rep1["power_gate"]["passed"], "synthetic power gate should pass"

    # anti-gaming regression: a LAZY condition that abstains on everything except a
    # few easy correct answers must NOT win the primary. It gets ~perfect SELECTIVE
    # accuracy but poor PRIMARY balanced accuracy (abstain=incorrect).
    lazy = []
    ans_budget = {"VULNERABLE": 4, "SAFE": 4}
    for r in labels:
        g = r["stage1_label"]
        if g in ("VULNERABLE", "SAFE") and ans_budget.get(g, 0) > 0:
            lazy.append({"instance_id": r["instance_id"], "condition": "LAZY", "prediction": g})
            ans_budget[g] -= 1
        else:
            lazy.append({"instance_id": r["instance_id"], "condition": "LAZY", "prediction": "ABSTAIN"})
    lz = H.condition_metrics({r["instance_id"]: r["stage1_label"] for r in labels},
                             {"LAZY": {x["instance_id"]: x["prediction"] for x in lazy}},
                             [r["instance_id"] for r in labels
                              if r["stage1_label"] in ("VULNERABLE", "SAFE")])["LAZY"]
    assert lz["selective_balanced_accuracy"] >= 0.99, "lazy should look great selectively"
    assert lz["primary_balanced_accuracy"] < 0.3, "lazy must lose on the primary metric"
    assert lz["primary_balanced_accuracy"] < rep1["per_condition"]["A"]["primary_balanced_accuracy"], \
        "primary metric failed to penalise strategic abstention"

    frozen = {
        "purpose": "freeze scoring_harness.py behaviour before real labels exist",
        "synthetic": True,
        "seed": SEED, "bootstrap": {"seed": H.BOOT_SEED, "n": H.BOOT_N},
        "sha256": {f: sha(os.path.join(HERE, f)) for f in
                   ("scoring_harness.py", "SCORING_PLAN.md")},
        "artifact_sha256": {os.path.basename(p): sha(p) for p in (lab_p, prd_p, exp_p)},
        "primary_point_synthetic": prim["point"],
        "primary_ci95_synthetic": prim["ci95"],
    }
    with open(os.path.join(OUT, "FROZEN.json"), "w") as fh:
        json.dump(frozen, fh, indent=2, sort_keys=True, default=str)

    print("synthetic class distribution (confirmatory):", rep1["class_distribution"])
    print("binary population:", rep1["binary_population"])
    print("power gate:", rep1["power_gate"]["passed"],
          f"(vuln_families={rep1['power_gate']['vulnerable_families']}, "
          f"safe_families={rep1['power_gate']['safe_families']}, "
          f"min={rep1['power_gate']['min_pos_families']})")
    print("primary metric:", rep1["primary_metric"])
    for c, m in sorted(rep1["per_condition"].items()):
        print(f"  {c}: PRIMARY balAcc(abstain=wrong)={m['primary_balanced_accuracy']:.3f} | "
              f"selective={m['selective_balanced_accuracy']:.3f} cov={m['coverage']:.3f} "
              f"abst={m['abstention_rate']:.3f} unresAppAbst={m['unresolved_appropriate_abstention']:.3f}")
    print(f"PRIMARY B-A (abstain=wrong): {prim['point']:.4f} CI95={prim['ci95']} "
          f"inference={prim['inference']} degenerate_frac={prim['degenerate_resample_frac']:.4f}")
    if "secondary_comparisons" in rep1:
        for k, v in rep1["secondary_comparisons"].items():
            print(f"  secondary {k}: {v['point']:.3f} CI {v['ci95']} holm_p={v.get('holm_p')}")
    print("\nDETERMINISM: PASS   SYNTHETIC EFFECT RECOVERED: PASS")
    print(f"frozen -> {OUT}/FROZEN.json (sha256 of harness, plan, synthetic inputs, expected report)")


if __name__ == "__main__":
    main()
