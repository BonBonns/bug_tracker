#!/usr/bin/env python3
"""Freeze the FULL-SecVulEval slice of the held-out corpus, per
PREREGISTER_SECVULEVAL_FULL.md (committed before this script's first run).
NO model calls, NO TChecker, NO manual per-site interpretation.

RULE 1 (map_write) and RULE 2 (family_id) are IMPORTED from the frozen
secvuleval_freeze.py and applied unchanged; the only adapter logic is the
pre-registered field-format handling. ENTIRE dataset, no early stop.

Usage: secvuleval_full_freeze.py <secvuleval_full.jsonl.gz> <hf_revision>
"""
import gzip
import hashlib
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secvuleval_freeze as S   # frozen map_write + family_id + frozen sets


def main():
    path, rev = sys.argv[1], sys.argv[2]
    raw = open(path, "rb").read()
    gz_sha = hashlib.sha256(raw).hexdigest()

    excl = Counter()
    sites, seen = [], set()
    with gzip.open(path, "rt") as fh:
        for line in fh:
            r = json.loads(line)
            cwes = set(r.get("cwe_list") or [])
            if "CWE-119" in cwes:
                excl["ambiguous_cwe_119"] += 1
                continue
            if not (cwes & S.INCLUDE_CWE):
                excl["other_cwe_not_write"] += 1
                continue
            if (r.get("project") or "").lower() in S.MAGMA_PROJECTS:
                excl["magma_overlap_project"] += 1
                continue
            key = (r["project"], r["commit_id"], r["filepath"], r["func_name"])
            if key in seen:
                excl["duplicate_site"] += 1
                continue
            seen.add(key)
            fb = r.get("func_body") or ""
            try:
                labeled = json.loads(r.get("changed_statements") or "[]")
            except Exception:
                labeled = []
            status, w = S.map_write(fb, labeled)
            rec = {"site_id": hashlib.sha256("|".join(key).encode()).hexdigest()[:16],
                   "project": r["project"], "commit_id": r["commit_id"],
                   "filepath": r["filepath"], "func_name": r["func_name"],
                   "cve_list": r.get("cve_list") or [], "cwe_list": sorted(cwes),
                   "is_vulnerable": bool(r.get("is_vulnerable")),
                   "func_body_sha256": hashlib.sha256(fb.encode()).hexdigest(),
                   "mapping_status": status}
            if status == "mapped":
                rec["write_kind"] = w[1]
                rec["write_dest"] = w[2]
                rec["write_line"] = w[3]
                sig, fid = S.family_id(fb, w)
                rec["family_signature"] = sig
                rec["family_id"] = fid
            sites.append(rec)

    mapped = [s for s in sites if s["mapping_status"] == "mapped"]
    mv = [s for s in mapped if s["is_vulnerable"]]
    fams = {s["family_id"] for s in mv}
    manifest = {
        "FROZEN": True, "model_calls": 0, "tchecker_used": False,
        "source": "arag0rn/SecVulEval FULL train split (25,440 rows), HuggingFace",
        "preregistration": "PREREGISTER_SECVULEVAL_FULL.md (committed before first run)",
        "hf_revision": rev,
        "input_jsonl_gz_sha256": gz_sha,
        "supersedes": "study/secvuleval/FROZEN_heldout.json (reachable-subset pilot; "
                      "stays frozen; contributed 0 pooled sites)",
        "rule_1_write_site_mapping": "IMPORTED unchanged: S.map_write (labeled statement "
                                     "-> unique write within +-3 lines, or sole write if "
                                     "no anchor).",
        "rule_2_family_assignment": "IMPORTED unchanged: S.family_id.",
        "inclusion": "exclude if CWE-119 in cwe_list; include iff cwe_list intersects "
                     "{CWE-787, CWE-122, CWE-120}; Magma projects excluded; in-source "
                     "dedup (project, commit_id, filepath, func_name); ENTIRE dataset, "
                     "no early stop.",
        "exclusions": dict(excl),
        "counts": {
            "sites_after_filters": len(sites),
            "mapping": dict(Counter(s["mapping_status"] for s in sites)),
            "mapped_total": len(mapped),
            "mapped_vulnerable": len(mv),
            "mapped_non_vulnerable": len(mapped) - len(mv),
            "vulnerable_families": len(fams),
            "family_by_vuln_count": dict(Counter(s["family_id"] for s in mv)),
            "by_project_mapped_vuln": dict(Counter(s["project"] for s in mv)),
            "by_write_kind_vuln": dict(Counter(s["write_kind"] for s in mv)),
        },
        "sites": sites,
    }
    outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "study",
                        "secvuleval_full", "FROZEN_heldout.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(manifest, open(outp, "w"), indent=2, sort_keys=True)
    print("SITES after filters:", len(sites), " exclusions:", dict(excl))
    print("MAPPING:", dict(Counter(s["mapping_status"] for s in sites)))
    print(f"MAPPED total {len(mapped)} (vulnerable {len(mv)} / non-vuln {len(mapped)-len(mv)})")
    print(f"VULNERABLE FAMILIES (this source alone): {len(fams)}")
    print("by project (top):", Counter(s["project"] for s in mv).most_common(12))
    print("frozen ->", outp)


if __name__ == "__main__":
    main()
