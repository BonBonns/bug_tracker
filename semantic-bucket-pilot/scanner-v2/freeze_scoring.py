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
    """Family-clustered synthetic labels (FAKE) in the three-field Stage-1 schema.
    The scored field is evidence_reference_conclusion (fixed neutral-reference target);
    sometimes diverges (e.g. program vulnerable but packet evidence unresolved) —
    only to exercise the harness, not a claim about the data."""
    fam_risk = {}
    rows = []
    lc = {"VULNERABLE": "vulnerable", "SAFE": "safe", "UNRESOLVED": "unresolved"}
    for r in instances:
        fam = r["family_id"]
        if fam not in fam_risk:
            fam_risk[fam] = rng.random()
        u = rng.random()
        if u < 0.08:
            psc = "UNRESOLVED"
        else:
            base = fam_risk[fam]
            pre = r["revision_side"] == "pre_patch"
            pv = base * (0.9 if pre else 0.25)
            psc = "VULNERABLE" if rng.random() < pv else "SAFE"
        # program_outcome: usually agrees, but when packet is unresolved the program
        # may still be safe/vulnerable/not_established (evidence-relative divergence).
        if psc == "UNRESOLVED":
            prog = rng.choice(["safe", "vulnerable", "not_established"])
            rel = "unresolved"
        else:
            prog = lc[psc]
            rel = "established" if rng.random() < 0.9 else "contradicted"
        rows.append({"instance_id": r["instance_id"],
                     "evidence_reference_conclusion": lc[psc],  # SCORED (fixed neutral-reference target)
                     "program_outcome": prog,                 # reported separately
                     "relationship_answer": rel})
    return rows


def synth_predictions(labels, rng):
    """Three conditions; B deliberately more accurate + better-calibrated than A;
    C weakest. Includes abstentions and a few parse errors."""
    acc = {"A": 0.66, "B": 0.82, "C": 0.58}
    abst = {"A": 0.18, "B": 0.10, "C": 0.22}
    parse = {"A": 0.03, "B": 0.01, "C": 0.02}
    rows = []
    gt = {r["instance_id"]: H.scored_label(r) for r in labels}
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
            row = {"instance_id": iid, "condition": cond, "prediction": p}
            if p in ("VULNERABLE", "SAFE"):
                # external adjudication (the ERROR metric): A rests on unsupported
                # assumptions more often than B.
                ua = {"A": 0.20, "B": 0.08, "C": 0.25}[cond]
                ext = rng.random() < ua
                row["external_unsupported_assumption"] = ext
                # self-report (descriptive): the model under-reports its own
                # unsupported assumptions (only ~40% of true ones are disclosed).
                row["self_reported_unsupported"] = bool(ext and rng.random() < 0.4)
            rows.append(row)
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
    assert rep1["minimum_inference_gate"]["passed"], "synthetic inference gate should pass"

    # ---- anti-gaming regression: BOTH failure modes must be penalised ----
    G = {r["instance_id"]: H.scored_label(r) for r in labels}
    allids = [r["instance_id"] for r in labels]

    def metrics_for(fn):
        preds = {i: fn(G[i]) for i in allids}
        return H.condition_metrics(G, {"X": preds}, allids)["X"]

    # (1) LAZY: abstain on all but a few easy resolved answers -> great SELECTIVE,
    #     but low resolved recalls and a depressed three-class primary.
    budget = {"VULNERABLE": [4], "SAFE": [4]}
    def lazy(g):
        if g in ("VULNERABLE", "SAFE") and budget[g][0] > 0:
            budget[g][0] -= 1
            return g
        return "ABSTAIN"
    lz = metrics_for(lazy)
    assert lz["selective_balanced_accuracy"] >= 0.99, "lazy should look great selectively"
    assert (lz["recall_vulnerable"] or 0) < 0.2 and (lz["recall_safe"] or 0) < 0.2, \
        "lazy resolved recalls should be low"
    assert lz["primary_macro_recall_3class"] < rep1["per_condition"]["B"]["primary_macro_recall_3class"], \
        "primary must penalise strategic abstention"

    # (2) OVERCONFIDENT: perfect on resolved, but NEVER abstains -> guesses on every
    #     UNRESOLVED. recall_unresolved must be ~0 and the primary must fall below a
    #     CALIBRATED twin that is identical on resolved but abstains on UNRESOLVED.
    over = metrics_for(lambda g: "VULNERABLE" if g == "UNRESOLVED" else g)
    cal = metrics_for(lambda g: "ABSTAIN" if g == "UNRESOLVED" else g)
    assert (over["recall_unresolved"] or 0) < 0.01, "overconfident should never abstain on UNRESOLVED"
    assert cal["primary_macro_recall_3class"] > over["primary_macro_recall_3class"], \
        "primary must penalise committing on truly-unresolved cases"
    assert cal["primary_macro_recall_3class"] >= 0.999, "calibrated-perfect should score ~1.0"

    frozen = {
        "purpose": "freeze scoring_harness.py behaviour before real labels exist",
        "synthetic": True,
        "WARNING": ("synthetic B-A scores are HARNESS REGRESSION OUTPUTS, not an "
                    "experimental finding. They vary with the synthetic seed, the "
                    "instance ids, and the synthetic inputs, and MUST NEVER appear in "
                    "the results section. Only the real Stage-2 run produces findings."),
        "seed": SEED, "bootstrap": {"seed": H.BOOT_SEED, "n": H.BOOT_N},
        "sha256": {f: sha(os.path.join(HERE, f)) for f in
                   ("scoring_harness.py", "SCORING_PLAN.md")},
        "artifact_sha256": {os.path.basename(p): sha(p) for p in (lab_p, prd_p, exp_p)},
        "primary_point_synthetic_REGRESSION_ONLY": prim["point"],
        "primary_ci95_synthetic_REGRESSION_ONLY": prim["ci95"],
    }
    with open(os.path.join(OUT, "FROZEN.json"), "w") as fh:
        json.dump(frozen, fh, indent=2, sort_keys=True, default=str)

    print("synthetic class distribution (confirmatory):", rep1["class_distribution"])
    print("population:", rep1["population"])
    g = rep1["minimum_inference_gate"]
    print(f"minimum inference gate: {g['passed']} (families_by_class={g['families_by_class']}, "
          f"min={g['min_class_families']}; {g['kind']})")
    print("primary metric:", rep1["primary_metric"])
    for c, m in sorted(rep1["per_condition"].items()):
        print(f"  {c}: PRIMARY macroRecall3={m['primary_macro_recall_3class']:.3f} "
              f"[V={m['recall_vulnerable']:.2f} S={m['recall_safe']:.2f} U={m['recall_unresolved']:.2f}] | "
              f"resolvedFC={m['resolved_full_coverage_balanced_accuracy']:.3f} "
              f"selective={m['selective_balanced_accuracy']:.3f} cov={m['coverage']:.3f} "
              f"extUnsup={m['external_unsupported_assumption_rate']} "
              f"selfRep={m['self_reported_unsupported_rate']}")
    print("scored field = evidence_reference_conclusion (ONE fixed neutral-reference target for A/B/C), NOT program_outcome")
    print("scored x program_outcome cross-tab:", rep1["program_outcome_crosstab_scored_x_program"])
    print(f"[REGRESSION ONLY, not a finding] PRIMARY B-A: {prim['point']:.4f} CI95={prim['ci95']} "
          f"inference={prim['inference']} degenerate_frac={prim['degenerate_resample_frac']:.4f}")
    if "secondary_comparisons" in rep1:
        for k, v in rep1["secondary_comparisons"].items():
            print(f"  secondary {k}: {v['point']:.3f} CI {v['ci95']} holm_p={v.get('holm_p')}")
    print("\nDETERMINISM: PASS   SYNTHETIC EFFECT RECOVERED: PASS   (synthetic numbers are NOT findings)")
    print(f"frozen -> {OUT}/FROZEN.json (sha256 of harness, plan, synthetic inputs, expected report)")


if __name__ == "__main__":
    main()
