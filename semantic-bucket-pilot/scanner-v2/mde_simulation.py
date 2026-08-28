#!/usr/bin/env python3
"""Minimum detectable effect (MDE) simulation for the three-class primary.

The MIN_CLASS_FAMILIES=12 gate is a minimum-count FLOOR, not a power guarantee.
This characterises the actual power of the frozen design: given the confirmatory
family structure (family sizes from instances.jsonl) and ASSUMED class prevalences,
simulate two conditions whose true three-class macro recall differs by delta, run
the frozen family-cluster bootstrap decision, and report empirical power vs delta.
Reports the MDE (smallest delta reaching 80% power) per assumed prevalence.

Assumptions are disclosed and swept; real prevalence is unknown until Stage 1.
This is supporting analysis, not a frozen artifact.
"""
import json
import os
import random
import statistics

import scoring_harness as H

HERE = os.path.dirname(os.path.abspath(__file__))
TRIALS = 100
BOOT = 600
BASE_RECALL = 0.60
DELTAS = [0.08, 0.12, 0.16, 0.20]
# assumed (VULNERABLE, UNRESOLVED) prevalence; SAFE = remainder
PREVALENCES = [("moderate", 0.15, 0.10), ("low_vuln", 0.08, 0.08), ("rich", 0.25, 0.15)]
CLASSES = H.CLASSES


def confirmatory_families():
    insts = [json.loads(l) for l in open(os.path.join(HERE, "study", "instances.jsonl"))]
    fam = {}
    for it in insts:
        if it["split"] == "confirmatory":
            fam.setdefault(it["family_id"], []).append(it["instance_id"])
    return fam


def sim_labels(fam, pv_v, pv_u, rng):
    gt = {}
    for f, ids in fam.items():
        risk = rng.random()
        for i in ids:
            u = rng.random()
            if u < pv_u:
                gt[i] = "UNRESOLVED"
            elif u < pv_u + pv_v * (0.5 + risk):     # family-clustered vuln rate
                gt[i] = "VULNERABLE"
            else:
                gt[i] = "SAFE"
    return gt


def sim_pred(gt, recall, rng):
    pred = {}
    other = {"VULNERABLE": ["SAFE", "ABSTAIN"], "SAFE": ["VULNERABLE", "ABSTAIN"],
             "UNRESOLVED": ["VULNERABLE", "SAFE"]}
    for i, g in gt.items():
        if rng.random() < recall:
            pred[i] = "ABSTAIN" if g == "UNRESOLVED" else g
        else:
            pred[i] = rng.choice(other[g])
    return pred


def _fam_stats(gt, pred, fam):
    """Per-family sufficient stats: tot[c], correct[c] over the 3 classes."""
    idx = {c: k for k, c in enumerate(CLASSES)}
    stats = {}
    for f, ids in fam.items():
        tot = [0, 0, 0]; cor = [0, 0, 0]
        for i in ids:
            g = gt[i]; k = idx[g]
            tot[k] += 1
            cor[k] += (H.pred_class(pred.get(i)) == g)
        stats[f] = (tot, cor)
    return stats


def light_bootstrap(gt, pa, pb, fam, rng):
    """Efficient family-cluster bootstrap over per-family class count vectors.
    Returns True iff the 95% CI of (B-A) macro-recall diff excludes 0 (positive)."""
    fams = list(fam.keys())
    F = len(fams)
    sa = _fam_stats(gt, pa, fam)
    sb = _fam_stats(gt, pb, fam)
    # flat per-family arrays indexed by position
    tv = [sa[f][0][0] for f in fams]; ts = [sa[f][0][1] for f in fams]; tu = [sa[f][0][2] for f in fams]
    av = [sa[f][1][0] for f in fams]; as_ = [sa[f][1][1] for f in fams]; au = [sa[f][1][2] for f in fams]
    bv = [sb[f][1][0] for f in fams]; bs = [sb[f][1][1] for f in fams]; bu = [sb[f][1][2] for f in fams]
    diffs = []
    degen = 0
    choices = rng.choices
    for _ in range(BOOT):
        idx = choices(range(F), k=F)
        TV = TS = TU = AV = AS = AU = BV = BS = BU = 0
        for j in idx:
            TV += tv[j]; TS += ts[j]; TU += tu[j]
            AV += av[j]; AS += as_[j]; AU += au[j]
            BV += bv[j]; BS += bs[j]; BU += bu[j]
        if TV == 0 or TS == 0 or TU == 0:
            degen += 1
            continue
        ma = (AV / TV + AS / TS + AU / TU) / 3
        mb = (BV / TV + BS / TS + BU / TU) / 3
        diffs.append(mb - ma)
    if not diffs or degen > BOOT * H.MAX_DEGENERATE_FRAC:
        return None
    diffs.sort()
    return diffs[int(0.025 * len(diffs))] > 0


def main():
    fam = confirmatory_families()
    rng = random.Random(7)
    print(f"confirmatory families={len(fam)}  instances={sum(len(v) for v in fam.values())}")
    print(f"TRIALS={TRIALS} BOOT={BOOT} base recall={BASE_RECALL}\n")
    out = {}
    for name, pv_v, pv_u in PREVALENCES:
        row = {}
        # report expected family-by-class counts once
        gt0 = sim_labels(fam, pv_v, pv_u, random.Random(1))
        fbc = {c: len({f for f, ids in fam.items() if any(gt0[i] == c for i in ids)})
               for c in CLASSES}
        mde = None
        for d in DELTAS:
            sig = 0
            for t in range(TRIALS):
                gt = sim_labels(fam, pv_v, pv_u, rng)
                pa = sim_pred(gt, BASE_RECALL, rng)
                pb = sim_pred(gt, min(0.99, BASE_RECALL + d), rng)
                r = light_bootstrap(gt, pa, pb, fam, rng)   # baseline A, better B
                if r:
                    sig += 1
            power = sig / TRIALS
            row[d] = round(power, 3)
            if mde is None and power >= 0.80:
                mde = d
        out[name] = {"prevalence_v": pv_v, "prevalence_u": pv_u,
                     "expected_families_by_class": fbc,
                     "power_by_delta": row, "mde_80pct": mde}
        print(f"{name:9} V={pv_v} U={pv_u}  families_by_class={fbc}")
        print(f"           power by delta: {row}   MDE@80%: {mde}")
    with open(os.path.join(HERE, "study", "mde_simulation.json"), "w") as fh:
        json.dump({"trials": TRIALS, "boot": BOOT, "base_recall": BASE_RECALL,
                   "results": out}, fh, indent=2, sort_keys=True)
    print("\nMDE simulation written to study/mde_simulation.json")
    print("NOTE: MIN_CLASS_FAMILIES=12 is a floor; this shows the true detectable "
          "effect given the cluster structure and assumed prevalences.")


if __name__ == "__main__":
    main()
