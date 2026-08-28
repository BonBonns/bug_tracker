#!/usr/bin/env python3
"""Stage 2 scoring harness — frozen implementation of SCORING_PLAN.md.

Inputs (all keyed by instance_id):
  --instances    study/instances.jsonl            (family_id, split)
  --labels       <jsonl>  rows: instance_id, stage1_label in {VULNERABLE,SAFE,UNRESOLVED}
  --predictions  <jsonl>  rows: instance_id, condition, prediction in
                          {VULNERABLE,SAFE,ABSTAIN,PARSE_ERROR}   (missing -> ABSTAIN)
  --split        confirmatory (default) | dev

No scoring parameter is chosen at run time; everything below is pre-registered.
Runs identically on synthetic and real data. Emits a report dict (stdout + JSON).
"""
import argparse
import json
import random
from collections import defaultdict

PRIMARY = ("B", "A")          # B - A
SECONDARY_COMPARISONS = [("C", "A"), ("B", "C")]
BOOT_SEED = 20260101
BOOT_N = 10000
ANSWERS = {"VULNERABLE", "SAFE"}


def load_jsonl(p):
    return [json.loads(l) for l in open(p)]


def selective_balanced_accuracy(gt, pred, ids):
    """Over the given instance ids: selective balanced accuracy, sensitivity,
    specificity, coverage. Abstain/parse -> not answered."""
    tp = fn_v = 0      # VULNERABLE answered
    tn = fp_s = 0      # SAFE answered
    ans_v = ans_s = tot_v = tot_s = 0
    for i in ids:
        g = gt.get(i)
        p = pred.get(i, "ABSTAIN")
        if p == "PARSE_ERROR":
            p = "ABSTAIN"
        if g == "VULNERABLE":
            tot_v += 1
            if p in ANSWERS:
                ans_v += 1
                if p == "VULNERABLE":
                    tp += 1
                else:
                    fn_v += 1
        elif g == "SAFE":
            tot_s += 1
            if p in ANSWERS:
                ans_s += 1
                if p == "SAFE":
                    tn += 1
                else:
                    fp_s += 1
    sens = tp / ans_v if ans_v else float("nan")
    spec = tn / ans_s if ans_s else float("nan")
    bal = (sens + spec) / 2 if (ans_v and ans_s) else float("nan")
    cov = (ans_v + ans_s) / (tot_v + tot_s) if (tot_v + tot_s) else float("nan")
    return {"selective_balanced_accuracy": bal, "sensitivity": sens,
            "specificity": spec, "coverage": cov,
            "answered_vuln": ans_v, "answered_safe": ans_s,
            "total_vuln": tot_v, "total_safe": tot_s}


def condition_metrics(gt, preds_by_cond, ids):
    out = {}
    for cond, pred in preds_by_cond.items():
        m = selective_balanced_accuracy(gt, pred, ids)
        # abstention/parse rates over VULN/SAFE instances
        n = abst = parse = 0
        for i in ids:
            if gt.get(i) in ANSWERS:
                n += 1
                p = pred.get(i, "ABSTAIN")
                if p == "PARSE_ERROR":
                    parse += 1; abst += 1
                elif p == "ABSTAIN":
                    abst += 1
        m["abstention_rate"] = abst / n if n else float("nan")
        m["parse_failure_rate"] = parse / n if n else float("nan")
        # sensitivity analysis: abstain = incorrect (balanced)
        m["balanced_accuracy_abstain_wrong"] = _bal_abstain_wrong(gt, pred, ids)
        # appropriate abstention on UNRESOLVED
        m["unresolved_appropriate_abstention"] = _unresolved_abst(gt, pred, ids)
        out[cond] = m
    return out


def _bal_abstain_wrong(gt, pred, ids):
    tp = tot_v = tn = tot_s = 0
    for i in ids:
        g = gt.get(i); p = pred.get(i, "ABSTAIN")
        if g == "VULNERABLE":
            tot_v += 1; tp += (p == "VULNERABLE")
        elif g == "SAFE":
            tot_s += 1; tn += (p == "SAFE")
    if not (tot_v and tot_s):
        return float("nan")
    return (tp / tot_v + tn / tot_s) / 2


def _unresolved_abst(gt, pred, ids):
    tot = appr = 0
    for i in ids:
        if gt.get(i) == "UNRESOLVED":
            tot += 1
            p = pred.get(i, "ABSTAIN")
            if p in ("ABSTAIN", "PARSE_ERROR"):
                appr += 1
    return appr / tot if tot else float("nan")


def paired_bootstrap(gt, preds_by_cond, fam_ids, hi, lo):
    """Family-cluster bootstrap of the paired difference in selective balanced
    accuracy, hi - lo. Returns (point, ci_low, ci_high, frac_gt0)."""
    families = list(fam_ids.keys())
    rng = random.Random(BOOT_SEED)

    def diff(sel_ids):
        a = selective_balanced_accuracy(gt, preds_by_cond[hi], sel_ids)["selective_balanced_accuracy"]
        b = selective_balanced_accuracy(gt, preds_by_cond[lo], sel_ids)["selective_balanced_accuracy"]
        return a - b

    all_ids = [i for f in families for i in fam_ids[f]]
    point = diff(all_ids)
    diffs = []
    for _ in range(BOOT_N):
        samp = [rng.choice(families) for _ in families]
        sel = [i for f in samp for i in fam_ids[f]]
        d = diff(sel)
        if d == d:      # not NaN
            diffs.append(d)
    diffs.sort()
    if not diffs:
        return point, float("nan"), float("nan"), float("nan")
    lo_ci = diffs[int(0.025 * len(diffs))]
    hi_ci = diffs[min(len(diffs) - 1, int(0.975 * len(diffs)))]
    frac = sum(1 for d in diffs if d > 0) / len(diffs)
    return point, lo_ci, hi_ci, frac


def holm(pvals):
    """Holm-Bonferroni adjusted p-values for a dict {name: p}."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    adj = {}
    running = 0.0
    for rank, (name, p) in enumerate(items):
        a = min(1.0, (m - rank) * p)
        running = max(running, a)
        adj[name] = running
    return adj


def two_sided_p(frac_gt0):
    # bootstrap two-sided p ~ 2*min(frac>0, frac<0)
    return min(1.0, 2 * min(frac_gt0, 1 - frac_gt0))


def run(instances, labels, predictions, split):
    inst = {r["instance_id"]: r for r in instances}
    gt = {r["instance_id"]: r["stage1_label"] for r in labels}
    preds_by_cond = defaultdict(dict)
    for r in predictions:
        preds_by_cond[r["condition"]][r["instance_id"]] = r["prediction"]
    preds_by_cond = dict(preds_by_cond)

    sel = [i for i, r in inst.items() if r["split"] == split]
    # families -> member instance ids (within split), restricted to VULN/SAFE for primary
    fam_ids_bin = defaultdict(list)
    for i in sel:
        if gt.get(i) in ANSWERS:
            fam_ids_bin[inst[i]["family_id"]].append(i)

    dist = {"VULNERABLE": 0, "SAFE": 0, "UNRESOLVED": 0, "UNLABELED": 0}
    for i in sel:
        dist[gt.get(i, "UNLABELED")] = dist.get(gt.get(i, "UNLABELED"), 0) + 1

    metrics = condition_metrics(gt, preds_by_cond, sel)

    report = {
        "split": split,
        "class_distribution": dist,
        "binary_population": {"instances": sum(len(v) for v in fam_ids_bin.values()),
                              "families": len(fam_ids_bin)},
        "per_condition": metrics,
    }
    # primary B - A
    hi, lo = PRIMARY
    if hi in preds_by_cond and lo in preds_by_cond and fam_ids_bin:
        pt, cl, ch, frac = paired_bootstrap(gt, preds_by_cond, fam_ids_bin, hi, lo)
        report["primary_comparison"] = {
            "comparison": f"{hi} - {lo}", "metric": "selective_balanced_accuracy",
            "point": pt, "ci95": [cl, ch], "excludes_zero": (cl > 0 or ch < 0),
            "bootstrap": {"seed": BOOT_SEED, "n": BOOT_N, "unit": "family"}}
    # secondary comparisons with Holm
    sec_p = {}
    sec = {}
    for a, b in SECONDARY_COMPARISONS:
        if a in preds_by_cond and b in preds_by_cond and fam_ids_bin:
            pt, cl, ch, frac = paired_bootstrap(gt, preds_by_cond, fam_ids_bin, a, b)
            sec[f"{a} - {b}"] = {"point": pt, "ci95": [cl, ch]}
            sec_p[f"{a} - {b}"] = two_sided_p(frac)
    if sec_p:
        adj = holm(sec_p)
        for k in sec:
            sec[k]["holm_p"] = adj[k]
        report["secondary_comparisons"] = sec
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instances", default="study/instances.jsonl")
    ap.add_argument("--labels", required=True)
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--split", default="confirmatory")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    rep = run(load_jsonl(a.instances), load_jsonl(a.labels),
              load_jsonl(a.predictions), a.split)
    s = json.dumps(rep, indent=2, sort_keys=True, default=str)
    if a.out:
        open(a.out, "w").write(s)
    print(s)


if __name__ == "__main__":
    main()
