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
    av, av_sha = (None, None)
    av_path = os.path.join(HERE, "study", "arvo", "FROZEN_heldout.json")
    if os.path.exists(av_path):        # third source per PREREGISTER_ARVO.md
        av, av_sha = load("study/arvo/FROZEN_heldout.json")
    svf, svf_sha = (None, None)        # fourth source per PREREGISTER_SECVULEVAL_FULL.md
    svf_path = os.path.join(HERE, "study", "secvuleval_full", "FROZEN_heldout.json")
    if os.path.exists(svf_path):
        svf, svf_sha = load("study/secvuleval_full/FROZEN_heldout.json")

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

    av_pool, av_dropped = [], Counter()
    if av is not None:
        bv_pool_pc = {(s["project"].lower(), s["commit_id"]) for s in bv_pool}
        bv_pool_shas = {s["diff_sha256"] for s in bv_pool}
        for s in [x for x in av["sites"] if x["mapping_status"] == "mapped"]:
            pck = (s["project"].lower(), s["fix_commit"])
            if s["fix_commit"] and pck in sv_proj_commit | mg_proj_commit | bv_pool_pc:
                av_dropped["dup_project_commit"] += 1
                continue
            if s["diff_sha256"] in pc_diff_shas | bv_pool_shas:
                av_dropped["dup_diff_sha"] += 1
                continue
            av_pool.append(s)

    svf_pool, svf_dropped = [], Counter()
    if svf is not None:
        bv_cves = {s["cve"] for s in bv_pool if s.get("cve")}
        bv_pc2 = {(s["project"].lower(), s["commit_id"]) for s in bv_pool}
        av_pc2 = {(s["project"].lower(), s["fix_commit"]) for s in av_pool
                  if s.get("fix_commit")}
        for s in [x for x in svf["sites"]
                  if x["mapping_status"] == "mapped" and x["is_vulnerable"]]:
            if set(s.get("cve_list") or []) & (pc_cves | bv_cves):
                svf_dropped["dup_cve"] += 1
                continue
            if (s["project"].lower(), s["commit_id"]) in bv_pc2 | av_pc2:
                svf_dropped["dup_project_commit"] += 1
                continue
            svf_pool.append(s)

    pool = [dict(s, pool_source="postcutoff") for s in pc_mapped] + \
           [dict(s, pool_source="bigvul") for s in bv_pool] + \
           [dict(s, pool_source="arvo") for s in av_pool] + \
           [dict(s, pool_source="secvuleval_full") for s in svf_pool]
    fams = Counter(s["family_id"] for s in pool)
    pc_fams = {s["family_id"] for s in pc_mapped}
    new_fams = {f for f in fams if f not in pc_fams}
    sv_vuln_fams = {s["family_id"] for s in sv_sites
                    if s["mapping_status"] == "mapped" and s.get("is_vulnerable")}

    manifest = {
        "FROZEN": True, "model_calls": 0, "tchecker_used": False,
        "preregistration": "PREREGISTER_BIGVUL.md (committed before bigvul_freeze ran)",
        "inputs_sha256": {"postcutoff": pc_sha, "secvuleval": sv_sha,
                          "bigvul": bv_sha, "magma_write_mapping": mg_sha,
                          "arvo": av_sha, "secvuleval_full": svf_sha},
        "dedup_rules": "pre-registered: drop Big-Vul mapped site on CVE match (PostCutoff/"
                       "SecVulEval), (project, fix commit) match (SecVulEval/Magma), or "
                       "identical diff_sha256 (PostCutoff); Magma projects excluded "
                       "wholesale at inclusion; family dedup at counting time "
                       "(distinct family_id counted once).",
        "bigvul_mapped_before_dedup": len(bv_mapped),
        "bigvul_dropped_by_dedup": dict(dropped),
        "bigvul_pooled": len(bv_pool),
        "arvo_mapped_before_dedup": (len([x for x in av["sites"]
                                          if x["mapping_status"] == "mapped"])
                                     if av is not None else None),
        "arvo_dropped_by_dedup": dict(av_dropped),
        "arvo_pooled": len(av_pool),
        "secvuleval_full_mapped_vuln_before_dedup": (
            len([x for x in svf["sites"]
                 if x["mapping_status"] == "mapped" and x["is_vulnerable"]])
            if svf is not None else None),
        "secvuleval_full_dropped_by_dedup": dict(svf_dropped),
        "secvuleval_full_pooled": len(svf_pool),
        "postcutoff_pooled": len(pc_mapped),
        "pooled_sites": len(pool),
        "pooled_vulnerable_families": len(fams),
        "family_sizes": dict(fams),
        "families_from_postcutoff": sorted(pc_fams),
        "families_new_from_bigvul": sorted({s["family_id"] for s in bv_pool}
                                           - pc_fams),
        "families_new_from_arvo": sorted({s["family_id"] for s in av_pool}
                                         - pc_fams
                                         - {s["family_id"] for s in bv_pool}),
        "families_new_from_secvuleval_full": sorted(
            {s["family_id"] for s in svf_pool}
            - pc_fams - {s["family_id"] for s in bv_pool}
            - {s["family_id"] for s in av_pool}),
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
    if av is not None:
        print("arvo pooled:", len(av_pool), " dropped:", dict(av_dropped))
    if svf is not None:
        print("secvuleval_full pooled:", len(svf_pool), " dropped:", dict(svf_dropped))
    print("POOLED sites:", len(pool), "  POOLED VULNERABLE FAMILIES:", len(fams),
          f" (12-gate: {'MEETS' if len(fams) >= 12 else 'BELOW'})")
    print("families beyond postcutoff's:", len(new_fams))
    print("magma-flagged families in pool:", sorted(f for f in fams if f in magma_fam_ids))
    print("frozen ->", outp)


if __name__ == "__main__":
    main()
