#!/usr/bin/env python3
"""Compute the held-out FUNNEL + recall summary from the ARCHIVED raw rows (raw_sites.jsonl)
and the frozen pooled manifest (for family denominators). Reads only archived data; makes NO
scanner calls and changes NO capability.

Reporting contract (audit requirements):
 * Vulnerable-only scope: recognition/COVERAGE, not precision/FPR/accuracy.
 * SecVulEval = recognition from frozen FUNCTION-LEVEL source packets (missing headers/decls/
   macros/callers/build config may lose evidence), NOT full-repository scanner recall.
 * Pipeline attrition (source not reconstructable / build / mapping) kept SEPARATE from
   scanner misses (mapped-but-unrecognized).
 * Identity chain asserted in aggregate: raw >= identity-bearing >= unique physical ops.
 * TWO measurements: (A) end-to-end COVERAGE, denom 258; (B) conditional scanner RECALL, denom
   = labeled sites mapped into a CPG.
 * Family: macro family recall = mean_f (recognized/all) and a conditional version over mapped;
   ">=1 site recognized in a family" is family COVERAGE, not recall.
 * Sensitivity analysis excluding the 5 pre-freeze-exposed sites and their 4 whole families.

Usage: heldout_summarize.py <heldout_run_dir>
"""
import json, os, sys
from collections import Counter, defaultdict

D = sys.argv[1] if len(sys.argv) > 1 else "study/heldout_run"
HERE = os.path.dirname(os.path.abspath(__file__))
rows = [json.loads(l) for l in open(os.path.join(D, "raw_sites.jsonl"))]
pool = json.load(open(os.path.join(HERE, "study", "pooled", "FROZEN_heldout_pooled.json")))

POOLED_TOTAL = 258
FAMILIES_TOTAL = 42
EXPOSED_SITES = {"ee5cad67577fa31d", "d232778c9a7f7df0", "6a970f8fab53b550",
                 "1a58eb99070d0fbe", "4aad12d8262078cf"}
EXPOSED_FAMILIES = {"fam_42418a7cbf67", "fam_83e36e70488c", "fam_9152d9e125ef",
                    "fam_bbab2acb2e20"}

# all pooled sites per family (denominator for strict macro recall; includes unrecoverable)
fam_all = Counter(s["family_id"] for s in pool["sites"])
all_families = set(fam_all)


def _rowkey(r):
    return r.get("site_id")


def recognized_site(r):
    return bool(r.get("stage4_recognized"))


def mapped_site(r):
    return bool(r.get("stage3_labeled_write_mapped"))


def compute(rows, fam_all, note=""):
    other = [r for r in rows if r["pool_source"] != "secvuleval_full"]
    sv = [r for r in rows if r["pool_source"] == "secvuleval_full"]
    s1 = [r for r in sv if r.get("stage1_source_available")]
    s2 = [r for r in s1 if r.get("stage2_build_parse_ok")]
    s3 = [r for r in s2 if mapped_site(r)]
    s4 = [r for r in s3 if recognized_site(r)]
    s5 = [r for r in s4 if r.get("stage5_evidence_established")]

    pool_total = sum(fam_all.values())
    recognized_total = len(s4)

    # (A) end-to-end coverage over the full pooled denominator
    coverage_A = (recognized_total, pool_total)
    # (B) conditional scanner recall over CPG-mapped sites
    recall_B = (recognized_total, len(s3))

    # macro family recall (strict): mean over ALL pooled families of recognized/all
    recog_by_fam = Counter(r["family_id"] for r in s4)
    mapped_by_fam = Counter(r["family_id"] for r in s3)
    strict_terms = {f: recog_by_fam.get(f, 0) / fam_all[f] for f in fam_all}
    macro_recall_strict = sum(strict_terms.values()) / len(fam_all) if fam_all else 0.0
    # conditional macro family recall: over families with >=1 mapped site, recognized/mapped
    cond_fams = [f for f in fam_all if mapped_by_fam.get(f, 0) > 0]
    cond_terms = {f: recog_by_fam.get(f, 0) / mapped_by_fam[f] for f in cond_fams}
    macro_recall_cond = (sum(cond_terms.values()) / len(cond_fams)) if cond_fams else 0.0
    # family COVERAGE (>=1 recognized), over all families and over families that reached scanner
    fam_cov_all = len([f for f in fam_all if recog_by_fam.get(f, 0) > 0])
    fam_cov_reached = len([f for f in cond_fams if recog_by_fam.get(f, 0) > 0])

    # identity reconciliation aggregate + chain assertion
    raw_r = idb = uniq = unver = 0
    for r in s2:
        ir = r.get("identity_reconciliation") or {}
        raw_r += ir.get("raw_recognized_records", 0)
        idb += ir.get("identity_bearing_records", 0)
        uniq += ir.get("unique_physical_operations", 0)
        unver += ir.get("identity_unverifiable_records", 0)
    assert raw_r >= idb >= uniq, (raw_r, idb, uniq)

    rel = Counter(r.get("stage6_relationship") for r in s4)
    scanner_miss = [r for r in s3 if not recognized_site(r)]
    return {
        "note": note,
        "counts": {"pooled": pool_total, "families": len(fam_all),
                   "other_not_reconstructable": len(other),
                   "s1_source_available": len(s1), "s2_build_parse_ok": len(s2),
                   "s3_mapped_into_cpg": len(s3), "s4_recognized": len(s4),
                   "s5_evidence_established": len(s5)},
        "relationship_of_recognized": dict(rel),
        "scanner_misses_by_write_kind": dict(Counter(r.get("write_kind") for r in scanner_miss)),
        "measurement_A_end_to_end_coverage": {"recognized": coverage_A[0], "denominator": coverage_A[1],
            "value": (coverage_A[0] / coverage_A[1] if coverage_A[1] else 0.0),
            "unrecovered_pipeline_attrition": coverage_A[1] - len(s3)},
        "measurement_B_conditional_scanner_recall": {"recognized": recall_B[0], "denominator": recall_B[1],
            "value": (recall_B[0] / recall_B[1] if recall_B[1] else 0.0)},
        "macro_family_recall_strict_over_all_families": macro_recall_strict,
        "macro_family_recall_conditional_over_mapped": macro_recall_cond,
        "family_coverage_ge1_recognized": {"over_all_families": [fam_cov_all, len(fam_all)],
            "over_families_reaching_scanner": [fam_cov_reached, len(cond_fams)]},
        "identity_reconciliation_aggregate": {
            "raw_recognized_records": raw_r, "identity_bearing_records": idb,
            "unique_physical_operations": uniq, "identity_unverifiable_records": unver,
            "chain_raw_ge_idbearing_ge_unique": bool(raw_r >= idb >= uniq)},
    }


def show(res):
    c = res["counts"]
    print(f"\n----- {res['note']} -----")
    print(f"pooled={c['pooled']} families={c['families']} "
          f"| not-reconstructable(pipeline)={c['other_not_reconstructable']}")
    print(f"FUNNEL (function-level source packets): s1={c['s1_source_available']} "
          f"s2_build={c['s2_build_parse_ok']} s3_mapped={c['s3_mapped_into_cpg']} "
          f"s4_recognized={c['s4_recognized']} s5_evidence={c['s5_evidence_established']}")
    print(f"relationship of recognized: {res['relationship_of_recognized']}")
    a = res["measurement_A_end_to_end_coverage"]
    b = res["measurement_B_conditional_scanner_recall"]
    print(f"(A) END-TO-END COVERAGE  = {a['recognized']}/{a['denominator']} = {100*a['value']:.2f}%  "
          f"(pipeline-unrecovered={a['unrecovered_pipeline_attrition']})")
    print(f"(B) CONDITIONAL RECALL   = {b['recognized']}/{b['denominator']} = {100*b['value']:.2f}%  "
          f"(denom = CPG-mapped labeled sites)")
    print(f"macro family recall (strict, /all-pooled-per-family, N={c['families']}) = "
          f"{100*res['macro_family_recall_strict_over_all_families']:.2f}%")
    print(f"macro family recall (conditional, /mapped-per-family) = "
          f"{100*res['macro_family_recall_conditional_over_mapped']:.2f}%")
    fc = res["family_coverage_ge1_recognized"]
    print(f"family COVERAGE (>=1 recognized): {fc['over_all_families'][0]}/{fc['over_all_families'][1]} "
          f"of all families; {fc['over_families_reaching_scanner'][0]}/"
          f"{fc['over_families_reaching_scanner'][1]} of families reaching the scanner")
    ir = res["identity_reconciliation_aggregate"]
    print(f"identity chain: raw={ir['raw_recognized_records']} >= "
          f"id-bearing={ir['identity_bearing_records']} >= unique={ir['unique_physical_operations']} "
          f"(unverifiable={ir['identity_unverifiable_records']}) OK={ir['chain_raw_ge_idbearing_ge_unique']}")


print("=" * 80)
print("HELD-OUT CONFIRMATORY RESULT  (vulnerable-only; recognition/COVERAGE, not precision)")
print("NOT perfectly blind: see PROTOCOL_DEVIATION.md (5 sites pre-exposed).")
print("SecVulEval = recognition from frozen FUNCTION-LEVEL source packets, not full-repo recall.")
print("=" * 80)

full = compute(rows, fam_all, "FULL (all pooled families/sites)")
show(full)

# sensitivity: drop the 5 exposed sites AND their 4 whole families
rows_sa = [r for r in rows if r.get("site_id") not in EXPOSED_SITES
           and r.get("family_id") not in EXPOSED_FAMILIES]
fam_all_sa = Counter({f: n for f, n in fam_all.items() if f not in EXPOSED_FAMILIES})
sens = compute(rows_sa, fam_all_sa, "SENSITIVITY (exclude 5 exposed sites + their 4 families)")
show(sens)

out = {"full": full, "sensitivity_excluding_exposed": sens,
       "protocol": "see PROTOCOL_DEVIATION.md; scanner unchanged (RUN_MANIFEST.json hashes)."}
json.dump(out, open(os.path.join(D, "SUMMARY.json"), "w"), indent=2, sort_keys=True)
print(f"\nwrote {os.path.join(D, 'SUMMARY.json')}")
