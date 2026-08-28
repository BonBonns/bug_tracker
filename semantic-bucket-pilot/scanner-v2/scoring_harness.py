#!/usr/bin/env python3
"""Stage 2 scoring harness — frozen implementation of SCORING_PLAN.md.

Inputs (all keyed by instance_id):
  --instances    study/instances.jsonl            (family_id, split)
  --labels       <jsonl>  rows: instance_id, stage1_label in {VULNERABLE,SAFE,UNRESOLVED}
  --predictions  <jsonl>  rows: instance_id, condition, prediction in
                          {VULNERABLE,SAFE,ABSTAIN,PARSE_ERROR}   (missing -> ABSTAIN);
                          optional booleans: 'external_unsupported_assumption'
                          (independent-adjudication ERROR metric) and
                          'self_reported_unsupported' (model self-report, DESCRIPTIVE).
  --split        confirmatory (default) | dev

Primary metric = three-class macro recall over {VULNERABLE, SAFE, UNRESOLVED}:
ABSTAIN is the model predicting UNRESOLVED, PARSE_ERROR is always incorrect. This
penalises abstaining on resolved cases AND committing on truly-unresolved cases.

No scoring parameter is chosen at run time; everything below is pre-registered.
Runs identically on synthetic and real data. Emits a report dict (stdout + JSON).
"""
import argparse
import json
import random
from collections import Counter, defaultdict

# Arms: A = code-only baseline; B = established facts + generic review;
#       C = established facts + bucket-guided category-and-question interface.
# The capability-effect question (does the bucket-guided interface help, evidence
# held constant) is C - B. B - C tests the COMBINED routing+questioning interface,
# NOT the bucket label alone (separating the two would need a 4th arm).
PRIMARY = ("C", "B")          # C - B  (bucket-guided interface effect)
SECONDARY_COMPARISONS = [("B", "A"), ("C", "A")]  # established-facts effect; combined
BOOT_SEED = 20260101
BOOT_N = 10000
CLASSES = ("VULNERABLE", "SAFE", "UNRESOLVED")
ANSWERS = {"VULNERABLE", "SAFE"}
MIN_CLASS_FAMILIES = 12       # minimum inference gate: each of the three classes
                              # must have >=12 families, else DESCRIPTIVE only.
                              # A minimum count floor, NOT demonstrated power; the
                              # achievable effect size is characterised separately
                              # by mde_simulation.py.
MAX_DEGENERATE_FRAC = 0.05    # if >5% of resamples miss a class, CI flagged non-robust.


def load_jsonl(p):
    return [json.loads(l) for l in open(p)]


def pred_class(p):
    """Map a raw prediction token to its class. ABSTAIN (or missing) is the model
    asserting UNRESOLVED; PARSE_ERROR is an invalid answer (never correct)."""
    if p is None or p == "ABSTAIN":
        return "UNRESOLVED"
    if p == "PARSE_ERROR":
        return "INVALID"
    return p                                    # VULNERABLE | SAFE


def macro_recall_3class(gt, pred, ids):
    """PRIMARY metric: three-class macro recall over {VULNERABLE, SAFE, UNRESOLVED}.
    gt in {VULNERABLE,SAFE,UNRESOLVED}; prediction mapped by pred_class (ABSTAIN ->
    UNRESOLVED, PARSE_ERROR -> INVALID which is always wrong). Penalises BOTH
    abstaining on resolved cases AND committing on truly-unresolved cases."""
    tot = {c: 0 for c in CLASSES}
    cor = {c: 0 for c in CLASSES}
    for i in ids:
        g = gt.get(i)
        if g not in CLASSES:
            continue
        tot[g] += 1
        cor[g] += (pred_class(pred.get(i)) == g)
    recalls = {c: cor[c] / tot[c] for c in CLASSES if tot[c] > 0}
    macro = sum(recalls.values()) / len(recalls) if recalls else float("nan")
    return {"macro_recall": macro, "recalls": recalls,
            "classes_present": len(recalls), "totals": tot}


def resolved_balanced_accuracy(gt, pred, ids, mode):
    """SECONDARY: resolved-class balanced accuracy over VULNERABLE/SAFE only.
    mode='full_coverage' -> ABSTAIN/PARSE count incorrect (denominators = totals);
    mode='selective'     -> answered only (denominators = answered)."""
    tp = tn = ans_v = ans_s = tot_v = tot_s = 0
    for i in ids:
        g = gt.get(i)
        p = pred.get(i, "ABSTAIN")
        if p == "PARSE_ERROR":
            p = "ABSTAIN"
        if g == "VULNERABLE":
            tot_v += 1
            if p in ANSWERS:
                ans_v += 1; tp += (p == "VULNERABLE")
        elif g == "SAFE":
            tot_s += 1
            if p in ANSWERS:
                ans_s += 1; tn += (p == "SAFE")
    dv, ds = (tot_v, tot_s) if mode == "full_coverage" else (ans_v, ans_s)
    sens = tp / dv if dv else float("nan")
    spec = tn / ds if ds else float("nan")
    bal = (sens + spec) / 2 if (dv and ds) else float("nan")
    cov = (ans_v + ans_s) / (tot_v + tot_s) if (tot_v + tot_s) else float("nan")
    return {"balanced_accuracy": bal, "sensitivity": sens, "specificity": spec,
            "coverage": cov}


def condition_metrics(gt, preds_by_cond, ids, extra_by_cond=None):
    extra_by_cond = extra_by_cond or {}
    out = {}
    for cond, pred in preds_by_cond.items():
        prim = macro_recall_3class(gt, pred, ids)
        rfc = resolved_balanced_accuracy(gt, pred, ids, "full_coverage")
        rsl = resolved_balanced_accuracy(gt, pred, ids, "selective")
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
            # PRIMARY: three-class macro recall
            "primary_macro_recall_3class": prim["macro_recall"],
            "recall_vulnerable": prim["recalls"].get("VULNERABLE"),
            "recall_safe": prim["recalls"].get("SAFE"),
            "recall_unresolved": prim["recalls"].get("UNRESOLVED"),
            # SECONDARY
            "resolved_full_coverage_balanced_accuracy": rfc["balanced_accuracy"],
            "selective_balanced_accuracy": rsl["balanced_accuracy"],
            "selective_sensitivity": rsl["sensitivity"],
            "selective_specificity": rsl["specificity"],
            "coverage": rfc["coverage"],
            "abstention_rate": abst / n if n else float("nan"),
            "parse_failure_rate": parse / n if n else float("nan"),
            # appropriate abstention on UNRESOLVED == recall_unresolved (kept explicit)
            "unresolved_appropriate_abstention": prim["recalls"].get("UNRESOLVED"),
            # ERROR metric: unsupported assumptions per INDEPENDENT adjudication
            # (a frozen external rubric over the response + ground-truth evidence),
            # NOT the model's self-report. None until adjudication exists.
            "external_unsupported_assumption_rate":
                _flag_rate(extra_by_cond.get(cond), "external_unsupported_assumption"),
            # DESCRIPTIVE only: the model's own self-report; unreliable as an error
            # metric (a model making an unsupported assumption may fail to list it).
            "self_reported_unsupported_rate":
                _flag_rate(extra_by_cond.get(cond), "self_reported_unsupported"),
        }
    return out


def _flag_rate(extra, field):
    """Fraction of a condition's committed (VULNERABLE/SAFE) answers whose `field`
    is truthy. Returns None if no row carries the field."""
    if not extra:
        return None
    committed = flagged = seen = 0
    for e in extra.values():
        if field not in e:
            continue
        seen += 1
        if e.get("prediction") in ANSWERS:
            committed += 1
            flagged += bool(e.get(field))
    if seen == 0:
        return None
    return flagged / committed if committed else None


def _classes_present(gt, ids):
    return sum(1 for c in CLASSES if any(gt.get(i) == c for i in ids))


def paired_bootstrap(gt, preds_by_cond, fam_ids, hi, lo):
    """Family-cluster bootstrap of the paired difference in the PRIMARY metric
    (three-class macro recall), hi - lo.

    Rare-class rule (pre-registered): a resample whose drawn families do not contain
    all three ground-truth classes leaves a class recall undefined; such resamples
    are DISCARDED (not redrawn), and the discard fraction is reported. If it exceeds
    MAX_DEGENERATE_FRAC the CI is flagged non-robust and descriptive results take
    precedence. Returns (point, ci_low, ci_high, frac_gt0, discard_frac)."""
    families = list(fam_ids.keys())
    rng = random.Random(BOOT_SEED)

    def diff(sel_ids):
        a = macro_recall_3class(gt, preds_by_cond[hi], sel_ids)["macro_recall"]
        b = macro_recall_3class(gt, preds_by_cond[lo], sel_ids)["macro_recall"]
        return a - b

    all_ids = [i for f in families for i in fam_ids[f]]
    point = diff(all_ids)
    diffs = []
    degenerate = 0
    for _ in range(BOOT_N):
        samp = [rng.choice(families) for _ in families]
        sel = [i for f in samp for i in fam_ids[f]]
        if _classes_present(gt, sel) < 3:      # a class missing -> recall undefined
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


_LMAP = {"safe": "SAFE", "vulnerable": "VULNERABLE", "unresolved": "UNRESOLVED",
         "not_established": "UNRESOLVED"}


def scored_label(r):
    """The class the PRIMARY scores: `evidence_reference_conclusion` — the conclusion
    supported by the FIXED neutral reference packet (shared code + the established
    scanner facts shared by B and C; no bucket, no focused C question, no condition
    id). It is ONE target identical for A, B and C, so the three conditions are
    scored against the same answer and remain comparable. NOT the program's real
    status. Accepts legacy field names. Normalises to {VULNERABLE, SAFE, UNRESOLVED}."""
    v = r.get("evidence_reference_conclusion",
              r.get("packet_supported_conclusion", r.get("stage1_label")))
    return _LMAP.get(str(v).lower(), v)


def run(instances, labels, predictions, split):
    inst = {r["instance_id"]: r for r in instances}
    gt = {r["instance_id"]: scored_label(r) for r in labels}
    # program_outcome is reported SEPARATELY and never scored by the primary.
    prog = {r["instance_id"]: r.get("program_outcome") for r in labels
            if r.get("program_outcome") is not None}
    preds_by_cond = defaultdict(dict)
    extra_by_cond = defaultdict(dict)
    for r in predictions:
        preds_by_cond[r["condition"]][r["instance_id"]] = r["prediction"]
        e = {"prediction": r["prediction"]}
        for f in ("external_unsupported_assumption", "self_reported_unsupported"):
            if f in r:
                e[f] = r[f]
        if len(e) > 1:
            extra_by_cond[r["condition"]][r["instance_id"]] = e
    preds_by_cond = dict(preds_by_cond)
    extra_by_cond = dict(extra_by_cond)

    # Independent fact validation: an instance whose packet rests on an INVALID
    # established fact is excluded from the main A/B/C analysis and reported
    # separately as an upstream evidence error (never scored as if the fact were
    # true). 'unresolved' fact validity stays in (the reviewer sets the reference
    # conclusion to unresolved unless the conclusion follows without that fact).
    facts_valid = {r["instance_id"]: r.get("established_facts_valid", "valid") for r in labels}
    split_all = [i for i, r in inst.items() if r["split"] == split]
    invalid_packets = [i for i in split_all if facts_valid.get(i) == "invalid"]
    sel = [i for i in split_all if facts_valid.get(i) != "invalid"]
    # families -> ALL three-class instance ids (the primary metric scores VULNERABLE,
    # SAFE and UNRESOLVED, so every labelled instance stays in the population).
    fam_ids_all = defaultdict(list)
    for i in sel:
        if gt.get(i) in CLASSES:
            fam_ids_all[inst[i]["family_id"]].append(i)

    dist = {"VULNERABLE": 0, "SAFE": 0, "UNRESOLVED": 0, "UNLABELED": 0}
    for i in sel:
        dist[gt.get(i, "UNLABELED")] = dist.get(gt.get(i, "UNLABELED"), 0) + 1

    # minimum inference gate: each of the three classes must reach MIN_CLASS_FAMILIES
    fams_by_class = {c: {inst[i]["family_id"] for i in sel if gt.get(i) == c} for c in CLASSES}
    class_fam_counts = {c: len(f) for c, f in fams_by_class.items()}
    gate_pass = all(v >= MIN_CLASS_FAMILIES for v in class_fam_counts.values())

    metrics = condition_metrics(gt, preds_by_cond, sel, extra_by_cond)

    # program_outcome reported SEPARATELY (never scored): cross-tab vs the scored
    # evidence-relative class, so "unresolved" is not mistaken for a program property.
    prog_crosstab = defaultdict(lambda: Counter())
    for i in sel:
        if i in prog:
            prog_crosstab[gt.get(i)][prog[i]] += 1
    prog_crosstab = {k: dict(v) for k, v in prog_crosstab.items()}

    report = {
        "split": split,
        "primary_metric": "three-class macro recall over {VULNERABLE, SAFE, UNRESOLVED} "
                          "(ABSTAIN=UNRESOLVED prediction; PARSE_ERROR incorrect)",
        "primary_scores": "evidence_reference_conclusion (ONE fixed neutral-reference "
                          "target, identical for A/B/C), NOT program_outcome",
        "primary_comparison_is": "C - B (bucket-guided interface effect, evidence held "
                                 "constant; combined category+question, not label alone)",
        "invalid_packets_excluded": {
            "count": len(invalid_packets),
            "note": ("packets whose established facts were independently judged INVALID; "
                     "excluded from the A/B/C analysis and reported as upstream evidence "
                     "errors, never scored as if the fact were true"),
            "fact_validity_distribution": dict(Counter(facts_valid.get(i, "valid") for i in split_all)),
        },
        "program_outcome_crosstab_scored_x_program": prog_crosstab,
        "class_distribution": dist,
        "population": {"instances": sum(len(v) for v in fam_ids_all.values()),
                       "families": len(fam_ids_all),
                       "families_by_class": class_fam_counts},
        "minimum_inference_gate": {
            "min_class_families": MIN_CLASS_FAMILIES,
            "families_by_class": class_fam_counts,
            "passed": gate_pass,
            "kind": "minimum-count floor, NOT demonstrated power",
            "rule": ("confirmatory CI computed only if every class reaches "
                     "MIN_CLASS_FAMILIES; otherwise DESCRIPTIVE point only. "
                     "See mde_simulation.py for the achievable effect size."),
        },
        "per_condition": metrics,
    }
    fam_ids_bin = fam_ids_all      # bootstrap population for the primary comparison

    def comparison(hi, lo):
        pt, cl, ch, frac, disc = paired_bootstrap(gt, preds_by_cond, fam_ids_bin, hi, lo)
        rec = {"comparison": f"{hi} - {lo}",
               "metric": "primary_macro_recall_3class", "point": pt,
               "degenerate_resample_frac": disc}
        if not gate_pass:
            rec["ci95"] = None
            rec["inference"] = "DESCRIPTIVE_ONLY_minimum_inference_gate_failed"
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
