#!/usr/bin/env python3
"""Freeze the POOLED held-out confirmatory population, per PREREGISTER_BIGVUL.md.
Pool = PostCutoff mapped vulnerable sites (unchanged) + Big-Vul mapped sites surviving
cross-source dedup. Dedup keys (pre-registered): CVE; (project, fix commit); identical
diff_sha256; Magma handled by wholesale project exclusion at inclusion time plus
family-level FLAGGING (frozen writes_in + family_id over the frozen Magma records).
Family dedup applies at counting time: distinct family_id counted once across the pool.

NO model calls, NO TChecker. Usage: pool_heldout_freeze.py
"""
import hashlib
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import secvuleval_freeze as S


def load(rel):
    p = os.path.join(HERE, rel)
    raw = open(p, "rb").read()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def magma_family_ids(magma_wm):
    """Structural family of each mapped Magma development bug, via the frozen rules."""
    out = {}
    for r in magma_wm["records"]:
        if r.get("status") != "mapped":
            continue
        ws = S.writes_in([r["write"]])
        if not ws:
            continue
        sig, fid = S.family_id(r.get("fix_diff", "") + "\n" + r["write"], ws[0])
        out[r["bug"]] = {"family_id": fid, "family_signature": sig,
                         "tgt": r["tgt"], "commit": r["commit"]}
    return out


def main():
    pc, pc_sha = load("study/postcutoff/FROZEN_heldout.json")
    sv, sv_sha = load("study/secvuleval/FROZEN_heldout.json")
    bv, bv_sha = load("study/bigvul/FROZEN_heldout.json")
    mg, mg_sha = load("study/magma/write_mapping.json")

    pc_mapped = [s for s in pc["sites"] if s["mapping_status"] == "mapped"]
    sv_sites = sv["sites"]
    bv_mapped = [s for s in bv["sites"] if s["mapping_status"] == "mapped"]

    pc_cves = {s["cve"] for s in pc_mapped if s.get("cve")}
    sv_cves = {s["cve"] for s in sv_sites if s.get("cve")}
    sv_proj_commit = {(s["project"].lower(), s["commit_id"]) for s in sv_sites}
    mg_proj_commit = {(r["tgt"].lower(), r["commit"]) for r in mg["records"]}
    pc_diff_shas = {s["diff_sha256"] for s in pc_mapped}
    magma_fams = magma_family_ids(mg)
    magma_fam_ids = {v["family_id"] for v in magma_fams.values()}

    dropped = Counter()
    bv_pool = []
    for s in bv_mapped:
        if s.get("cve") and (s["cve"] in pc_cves or s["cve"] in sv_cves):
            dropped["dup_cve"] += 1
            continue
        if (s["project"].lower(), s["commit_id"]) in sv_proj_commit | mg_proj_commit:
            dropped["dup_project_commit"] += 1
            continue
        if s["diff_sha256"] in pc_diff_shas:
            dropped["dup_diff_sha"] += 1
            continue
        bv_pool.append(s)

    pool = [dict(s, pool_source="postcutoff") for s in pc_mapped] + \
           [dict(s, pool_source="bigvul") for s in bv_pool]
    fams = Counter(s["family_id"] for s in pool)
    pc_fams = {s["family_id"] for s in pc_mapped}
    new_fams = {f for f in fams if f not in pc_fams}
    sv_vuln_fams = {s["family_id"] for s in sv_sites
                    if s["mapping_status"] == "mapped" and s.get("is_vulnerable")}

    manifest = {
        "FROZEN": True, "model_calls": 0, "tchecker_used": False,
        "preregistration": "PREREGISTER_BIGVUL.md (committed before bigvul_freeze ran)",
        "inputs_sha256": {"postcutoff": pc_sha, "secvuleval": sv_sha,
                          "bigvul": bv_sha, "magma_write_mapping": mg_sha},
        "dedup_rules": "pre-registered: drop Big-Vul mapped site on CVE match (PostCutoff/"
                       "SecVulEval), (project, fix commit) match (SecVulEval/Magma), or "
                       "identical diff_sha256 (PostCutoff); Magma projects excluded "
                       "wholesale at inclusion; family dedup at counting time "
                       "(distinct family_id counted once).",
        "bigvul_mapped_before_dedup": len(bv_mapped),
        "bigvul_dropped_by_dedup": dict(dropped),
        "bigvul_pooled": len(bv_pool),
        "postcutoff_pooled": len(pc_mapped),
        "pooled_sites": len(pool),
        "pooled_vulnerable_families": len(fams),
        "family_sizes": dict(fams),
        "families_from_postcutoff": sorted(pc_fams),
        "families_new_from_bigvul": sorted(new_fams),
        "secvuleval_pilot_families_subsumed": sorted(sv_vuln_fams),
        "magma_development_families_flagged": sorted(
            f for f in fams if f in magma_fam_ids),
        "magma_family_map": magma_fams,
        "twelve_vuln_family_gate": {"gate": 12,
                                    "vulnerable_families": len(fams),
                                    "meets_gate": len(fams) >= 12},
        "confirmatory_protocol": "Run ALL frozen capabilities once on the pooled mapped "
                                 "sites after branch reconciliation freezes ONE definitive "
                                 "scanner commit; score exact-site recognition/evidence/"
                                 "route against external labels. No capability designed or "
                                 "tuned using any result from this corpus. Yields NOT "
                                 "inspected. No held-out scanner measurement before "
                                 "reconciliation.",
        "sites": pool,
    }
    outp = os.path.join(HERE, "study", "pooled", "FROZEN_heldout_pooled.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(manifest, open(outp, "w"), indent=2, sort_keys=True)
    print("bigvul mapped:", len(bv_mapped), " dropped:", dict(dropped),
          " pooled from bigvul:", len(bv_pool))
    print("POOLED sites:", len(pool), "  POOLED VULNERABLE FAMILIES:", len(fams),
          f" (12-gate: {'MEETS' if len(fams) >= 12 else 'BELOW'})")
    print("new families from bigvul:", len(new_fams))
    print("magma-flagged families in pool:", sorted(f for f in fams if f in magma_fam_ids))
    print("frozen ->", outp)


if __name__ == "__main__":
    main()
