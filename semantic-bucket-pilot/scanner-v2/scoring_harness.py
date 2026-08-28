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
MIN_POS_FAMILIES = 12         # power gate: need >=12 families with a VULNERABLE
                              # instance AND >=12 with a SAFE instance, else no CI.
MAX_DEGENERATE_FRAC = 0.05    # if >5% of resamples are class-degenerate past the
                              # gate, the CI is flagged non-robust.


def load_jsonl(p):
    return [json.loads(l) for l in open(p)]


def balanced_accuracy(gt, pred, ids, mode):
    """Balanced accuracy over the given instance ids.
    mode='primary'  : denominators are TOTAL VULNERABLE / TOTAL SAFE, so an ABSTAIN
                      or PARSE_ERROR counts as an incorrect answer (cannot be gamed
                      by abstaining on hard cases).
    mode='selective': denominators are ANSWERED only (secondary; reward for
                      abstaining, reported alongside coverage)."""
    tp = tn = ans_v = ans_s = tot_v = tot_s = 0
    for i in ids:
        g = gt.get(i)
        p = pred.get(i, "ABSTAIN")
        if p == "PARSE_ERROR":
            p = "ABSTAIN"
        if g == "VULNERABLE":
            tot_v += 1
            if p in ANSWERS:
                ans_v += 1
                tp += (p == "VULNERABLE")
        elif g == "SAFE":
            tot_s += 1
            if p in ANSWERS:
                ans_s += 1
                tn += (p == "SAFE")
    dv, ds = (tot_v, tot_s) if mode == "primary" else (ans_v, ans_s)
    sens = tp / dv if dv else float("nan")
    spec = tn / ds if ds else float("nan")
    bal = (sens + spec) / 2 if (dv and ds) else float("nan")
    cov = (ans_v + ans_s) / (tot_v + tot_s) if (tot_v + tot_s) else float("nan")
    return {"balanced_accuracy": bal, "sensitivity": sens, "specificity": spec,
            "coverage": cov, "answered_vuln": ans_v, "answered_safe": ans_s,
            "total_vuln": tot_v, "total_safe": tot_s}


def condition_metrics(gt, preds_by_cond, ids):
    out = {}
    for cond, pred in preds_by_cond.items():
        prim = balanced_accuracy(gt, pred, ids, "primary")
        selv = balanced_accuracy(gt, pred, ids, "selective")
        n = abst = parse = 0
        for i in ids:
            if gt.get(i) in ANSWERS:
                n += 1
                p = pred.get(i, "ABSTAIN")
                if p == "PARSE_ERROR":
                    parse += 1; abst += 1
                elif p == "ABSTAIN":
                    abst += 1
        out[cond] = {
            # PRIMARY: abstain/parse counted incorrect (cannot be gamed)
            "primary_balanced_accuracy": prim["balanced_accuracy"],
            "primary_sensitivity": prim["sensitivity"],
            "primary_specificity": prim["specificity"],
            # SECONDARY: selective (answered only) + coverage
            "selective_balanced_accuracy": selv["balanced_accuracy"],
            "selective_sensitivity": selv["sensitivity"],
            "selective_specificity": selv["specificity"],
            "coverage": prim["coverage"],
            "abstention_rate": abst / n if n else float("nan"),
            "parse_failure_rate": parse / n if n else float("nan"),
            # SEPARATE: appropriate abstention on ground-truth UNRESOLVED
            "unresolved_appropriate_abstention": _unresolved_abst(gt, pred, ids),
        }
    return out


def _unresolved_abst(gt, pred, ids):
    tot = appr = 0
    for i in ids:
        if gt.get(i) == "UNRESOLVED":
            tot += 1
            p = pred.get(i, "ABSTAIN")
            if p in ("ABSTAIN", "PARSE_ERROR"):
                appr += 1
    return appr / tot if tot else float("nan")


def _class_counts(gt, ids):
    v = sum(1 for i in ids if gt.get(i) == "VULNERABLE")
    s = sum(1 for i in ids if gt.get(i) == "SAFE")
    return v, s


def paired_bootstrap(gt, preds_by_cond, fam_ids, hi, lo):
    """Family-cluster bootstrap of the paired difference in the PRIMARY metric
    (full-population balanced accuracy, abstain/parse = incorrect), hi - lo.

    Rare-class rule (pre-registered): a resample whose drawn families contain 0
    VULNERABLE or 0 SAFE instances leaves balanced accuracy undefined; such
    resamples are DISCARDED (not redrawn), and the discard fraction is reported.
    If the discard fraction exceeds MAX_DEGENERATE_FRAC the CI is flagged
    non-robust and descriptive results take precedence. Returns
    (point, ci_low, ci_high, frac_gt0, discard_frac)."""
    families = list(fam_ids.keys())
    rng = random.Random(BOOT_SEED)

    def diff(sel_ids):
        a = balanced_accuracy(gt, preds_by_cond[hi], sel_ids, "primary")["balanced_accuracy"]
        b = balanced_accuracy(gt, preds_by_cond[lo], sel_ids, "primary")["balanced_accuracy"]
        return a - b

    all_ids = [i for f in families for i in fam_ids[f]]
    point = diff(all_ids)
    diffs = []
    degenerate = 0
    for _ in range(BOOT_N):
        samp = [rng.choice(families) for _ in families]
        sel = [i for f in samp for i in fam_ids[f]]
        v, s = _class_counts(gt, sel)
        if v == 0 or s == 0:            # class-degenerate: balanced acc undefined
            degenerate += 1
            continue
        diffs.append(diff(sel))
    discard_frac = degenerate / BOOT_N
    diffs.sort()
    if not diffs:
        return point, float("nan"), float("nan"), float("nan"), discard_frac
    lo_ci = diffs[int(0.025 * len(diffs))]
    hi_ci = diffs[min(len(diffs) - 1, int(0.975 * len(diffs)))]
    frac = sum(1 for d in diffs if d > 0) / len(diffs)
    return point, lo_ci, hi_ci, frac, discard_frac


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
    # families -> their VULNERABLE/SAFE instance ids (answered or not — the primary
    # metric penalises abstention, so non-answers stay in the population).
    fam_ids_bin = defaultdict(list)
    for i in sel:
        if gt.get(i) in ANSWERS:
            fam_ids_bin[inst[i]["family_id"]].append(i)

    dist = {"VULNERABLE": 0, "SAFE": 0, "UNRESOLVED": 0, "UNLABELED": 0}
    for i in sel:
        dist[gt.get(i, "UNLABELED")] = dist.get(gt.get(i, "UNLABELED"), 0) + 1

    # power gate: independently-labelled families carrying each class
    vuln_fams = {inst[i]["family_id"] for i in sel if gt.get(i) == "VULNERABLE"}
    safe_fams = {inst[i]["family_id"] for i in sel if gt.get(i) == "SAFE"}
    gate_pass = (len(vuln_fams) >= MIN_POS_FAMILIES and len(safe_fams) >= MIN_POS_FAMILIES)

    metrics = condition_metrics(gt, preds_by_cond, sel)

    report = {
        "split": split,
        "primary_metric": "full-population balanced accuracy (ABSTAIN/PARSE=incorrect)",
        "class_distribution": dist,
        "binary_population": {"instances": sum(len(v) for v in fam_ids_bin.values()),
                              "families": len(fam_ids_bin),
                              "vulnerable_families": len(vuln_fams),
                              "safe_families": len(safe_fams)},
        "power_gate": {"min_pos_families": MIN_POS_FAMILIES,
                       "vulnerable_families": len(vuln_fams),
                       "safe_families": len(safe_fams),
                       "passed": gate_pass,
                       "rule": ("confirmatory CI computed only if both classes reach "
                                "MIN_POS_FAMILIES; otherwise DESCRIPTIVE point only")},
        "per_condition": metrics,
    }

    def comparison(hi, lo):
        pt, cl, ch, frac, disc = paired_bootstrap(gt, preds_by_cond, fam_ids_bin, hi, lo)
        rec = {"comparison": f"{hi} - {lo}",
               "metric": "primary_balanced_accuracy", "point": pt,
               "degenerate_resample_frac": disc}
        if not gate_pass:
            rec["ci95"] = None
            rec["inference"] = "DESCRIPTIVE_ONLY_power_gate_failed"
        elif disc > MAX_DEGENERATE_FRAC:
            rec["ci95"] = [cl, ch]
            rec["inference"] = "CI_FLAGGED_NON_ROBUST_high_degenerate_fraction"
            rec["excludes_zero"] = (cl > 0 or ch < 0)
        else:
            rec["ci95"] = [cl, ch]
            rec["excludes_zero"] = (cl > 0 or ch < 0)
            rec["inference"] = "confirmatory"
        rec["_frac_gt0"] = frac
        return rec

    hi, lo = PRIMARY
    if hi in preds_by_cond and lo in preds_by_cond and fam_ids_bin:
        pc = comparison(hi, lo)
        pc["bootstrap"] = {"seed": BOOT_SEED, "n": BOOT_N, "unit": "family"}
        report["primary_comparison"] = pc

    sec_p, sec = {}, {}
    for a, b in SECONDARY_COMPARISONS:
        if a in preds_by_cond and b in preds_by_cond and fam_ids_bin:
            rec = comparison(a, b)
            sec_p[f"{a} - {b}"] = two_sided_p(rec.pop("_frac_gt0"))
            sec[f"{a} - {b}"] = rec
    if sec_p and gate_pass:
        adj = holm(sec_p)
        for k in sec:
            sec[k]["holm_p"] = adj[k]
    if sec:
        report["secondary_comparisons"] = sec
    if "primary_comparison" in report:
        report["primary_comparison"].pop("_frac_gt0", None)
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
