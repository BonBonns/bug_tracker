#!/usr/bin/env python3
"""Compute the held-out FUNNEL + recall summary from the ARCHIVED raw rows (raw_sites.jsonl).
Pipeline attrition (stages 1-3) is kept SEPARATE from scanner misses (mapped-but-unrecognized).
Reads only the raw archive; makes NO scanner calls and changes NO capability. Vulnerable-only
scope: this is recognition/recall & coverage, not precision/FPR.

Usage: heldout_summarize.py <heldout_run_dir>
"""
import json, os, sys
from collections import Counter, defaultdict

D = sys.argv[1] if len(sys.argv) > 1 else "study/heldout_run"
rows = [json.loads(l) for l in open(os.path.join(D, "raw_sites.jsonl"))]

POOLED_TOTAL = 258
FAMILIES_TOTAL = 42

# ---- partition ---------------------------------------------------------------------------
other = [r for r in rows if r["pool_source"] != "secvuleval_full"]       # 83 metadata-only
sv = [r for r in rows if r["pool_source"] == "secvuleval_full"]

s1 = [r for r in sv if r.get("stage1_source_available")]
s2 = [r for r in s1 if r.get("stage2_build_parse_ok")]
s3 = [r for r in s2 if r.get("stage3_labeled_write_mapped")]
s4 = [r for r in s3 if r.get("stage4_recognized")]
s5 = [r for r in s4 if r.get("stage5_evidence_established")]

# pipeline attrition buckets (kept separate from scanner misses)
pipe = Counter()
for r in other:
    pipe["source_unavailable_metadata_only_source"] += 1
for r in sv:
    if not r.get("stage1_source_available"):
        pipe["stage1_source_missing"] += 1
    elif not r.get("stage2_build_parse_ok"):
        pipe["stage2_build_parse_failed"] += 1
    elif not r.get("stage3_labeled_write_mapped"):
        pipe["stage3_labeled_write_not_mapped"] += 1
scanner_miss = [r for r in s3 if not r.get("stage4_recognized")]

rel = Counter(r.get("stage6_relationship") for r in s4)

def pct(a, b):
    return f"{a}/{b} = {100.0*a/b:.1f}%" if b else f"{a}/0"

print("=" * 78)
print("HELD-OUT CONFIRMATORY FUNNEL  (vulnerable-only recognition/recall & coverage)")
print("=" * 78)
print(f"Pooled corpus: {POOLED_TOTAL} vulnerable sites / {FAMILIES_TOTAL} families "
      f"(0 non-vulnerable). Measures recognition/recall, NOT precision/FPR.\n")

print("PIPELINE ATTRITION (kept SEPARATE from scanner misses):")
for k, v in pipe.most_common():
    print(f"   {k}: {v}")
print(f"   -> {sum(pipe.values())} of {POOLED_TOTAL} sites never reached scanner recognition "
      f"for pipeline reasons (mostly the 83 metadata-only PostCutoff/BigVul/ARVO sites).\n")

print("FUNNEL over the source-reconstructable SecVulEval slice:")
print(f"   1. source available ....................... {len(s1)}")
print(f"   2. build/parse successful ................. {pct(len(s2), len(s1))}")
print(f"   3. labeled write mapped into CPG .......... {pct(len(s3), len(s2))}")
print(f"   4. physical site recognized by a producer . {pct(len(s4), len(s3))}")
print(f"   5. capacity/contract evidence established . {pct(len(s5), len(s4))}")
print(f"   6. relationship (of recognized): resolved={rel.get('resolved',0)} "
      f"open={rel.get('open',0)} missing={rel.get('missing',0)}\n")

print("SCANNER MISSES (mapped but NOT recognized) by labeled write_kind:")
for k, v in Counter(r.get("write_kind") for r in scanner_miss).most_common():
    print(f"   {k}: {v}")
print()

print("7. PER-SITE RECOGNITION RECALL (numerator = recognized):")
print(f"   over sites that reached the scanner (mapped, stage 3): {pct(len(s4), len(s3))}")
print(f"   over built sites (stage 2) .........................: {pct(len(s4), len(s2))}")
print(f"   over source-available SecVulEval (stage 1) .........: {pct(len(s4), len(s1))}")
print(f"   over the FULL pooled corpus (258) ..................: {pct(len(s4), POOLED_TOTAL)}\n")

# ---- 8. family-clustered recall ----------------------------------------------------------
fam_reached = defaultdict(int)     # families with >=1 site that reached the scanner (mapped)
fam_recog = defaultdict(int)       # families with >=1 recognized site
for r in s3:
    fam_reached[r["family_id"]] += 1
for r in s4:
    fam_recog[r["family_id"]] += 1
fam_reached_n = len(fam_reached)
fam_recog_n = len([f for f in fam_reached if fam_recog.get(f)])
all_fams = set(r["family_id"] for r in rows)
print("8. FAMILY-CLUSTERED RECOGNITION RECALL:")
print(f"   families present in pooled corpus ................: {len(all_fams)} (target {FAMILIES_TOTAL})")
print(f"   families with >=1 site reaching the scanner (mapped): {fam_reached_n}")
print(f"   families with >=1 RECOGNIZED site ................: {pct(fam_recog_n, fam_reached_n)} "
      f"(of families that reached the scanner)")
print(f"   families recognized over ALL pooled families ....: {pct(fam_recog_n, len(all_fams))}")
recog_fams = sorted(f for f in fam_reached if fam_recog.get(f))
print(f"   recognized families: {recog_fams}\n")

# distinct recognized operations (deduped through the frozen physical-write identity)
distinct_ops = sum(r.get("distinct_recognized_ops", 0) for r in s2)
prov = Counter()
for r in s2:
    for op in r.get("recognized_provenance", []):
        for p in op.get("provenance", []):
            prov[p["producer"]] += 1
print("DISTINCT RECOGNIZED OPERATIONS (deduped via frozen physical-write identity, "
      "all body writes not just labeled):")
print(f"   distinct recognized write operations across built bodies: {distinct_ops}")
print(f"   provenance contributions by producer/capability: {dict(prov)}")

summary = {
    "pooled_total": POOLED_TOTAL, "families_total": FAMILIES_TOTAL,
    "pipeline_attrition": dict(pipe),
    "funnel_secvuleval": {"s1_source_available": len(s1), "s2_build_parse_ok": len(s2),
                          "s3_labeled_write_mapped": len(s3), "s4_recognized": len(s4),
                          "s5_evidence_established": len(s5), "s6_relationship": dict(rel)},
    "scanner_misses_by_write_kind": dict(Counter(r.get("write_kind") for r in scanner_miss)),
    "per_site_recall": {"over_mapped": [len(s4), len(s3)], "over_built": [len(s4), len(s2)],
                        "over_source_available": [len(s4), len(s1)],
                        "over_pooled_258": [len(s4), POOLED_TOTAL]},
    "family_recall": {"families_in_pool": len(all_fams), "families_reached_scanner": fam_reached_n,
                      "families_recognized": fam_recog_n, "recognized_families": recog_fams},
    "distinct_recognized_operations": distinct_ops,
    "provenance_by_producer": dict(prov),
}
json.dump(summary, open(os.path.join(D, "SUMMARY.json"), "w"), indent=2, sort_keys=True)
print(f"\nwrote {os.path.join(D, 'SUMMARY.json')}")
