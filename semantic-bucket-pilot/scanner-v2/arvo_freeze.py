#!/usr/bin/env python3
"""Freeze the ARVO-Meta slice of the held-out confirmatory corpus, per
PREREGISTER_ARVO.md (committed before this script's first run). NO model calls,
NO TChecker, NO manual per-site interpretation.

RULE 1 and RULE 2 are IMPORTED from the frozen modules and applied unchanged to each
site's fix diff. The ENTIRE meta folder is processed; no early stop.

Usage: arvo_freeze.py <arvo_meta_repo_dir> <pinned_repo_commit>
"""
import hashlib
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secvuleval_freeze as S
import postcutoff_freeze as P

WRITE_CRASH = ("Heap-buffer-overflow WRITE", "Stack-buffer-overflow WRITE",
               "Global-buffer-overflow WRITE")
MAGMA_NAMES = {p.lower() for p in S.MAGMA_PROJECTS} | \
              {r.split("/")[-1].lower() for r in P.MAGMA_REPOS} | \
              {r.split("/")[0].lower() for r in P.MAGMA_REPOS}
C_CPP = re.compile(r"\.(c|cc|cpp|cxx|h|hpp)\b")   # postcutoff's exact test


def main():
    d, repo_commit = sys.argv[1], sys.argv[2]
    meta_dir = os.path.join(d, "archive_data", "meta")
    patch_dir = os.path.join(d, "archive_data", "patches")

    excl = Counter()
    sites = []
    seen_pc, seen_sha = set(), set()
    names = sorted(os.listdir(meta_dir), key=lambda n: (len(n), n))
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            m = json.load(open(os.path.join(meta_dir, name)))
        except Exception:
            excl["meta_unparseable"] += 1
            continue
        lid = m.get("localId")
        crash = (m.get("crash_type") or "").strip()
        if not crash.startswith(WRITE_CRASH):
            excl["not_write_crash_type"] += 1
            continue
        proj = (m.get("project") or "").strip()
        if proj.lower() in MAGMA_NAMES:
            excl["magma_overlap_project"] += 1
            continue
        fix = (m.get("fix") or "").rstrip("/")
        commit = fix.rsplit("/", 1)[-1] if fix else ""
        pp = os.path.join(patch_dir, f"{lid}.diff")
        if not os.path.exists(pp):
            excl["no_patch_file"] += 1
            continue
        diff = open(pp, errors="replace").read()
        if not C_CPP.search(diff):
            excl["not_c_cpp"] += 1
            continue
        if commit and (proj.lower(), commit) in seen_pc:
            excl["duplicate_project_commit"] += 1
            continue
        dsha = hashlib.sha256(diff.encode()).hexdigest()
        if dsha in seen_sha:
            excl["duplicate_diff_sha"] += 1
            continue
        if commit:
            seen_pc.add((proj.lower(), commit))
        seen_sha.add(dsha)
        lines = P.diff_hunk_lines(diff)
        ws = S.writes_in(lines)
        if not ws:
            status = "no_write_found"
        else:
            uniq = {(w[1], w[2]) for w in ws}   # frozen: unique (kind, dest)
            status = "mapped" if len(uniq) == 1 else "ambiguous"
        rec = {"local_id": lid, "project": proj, "crash_type": crash,
               "sanitizer": m.get("sanitizer"), "fix_commit": commit,
               "diff_sha256": dsha, "mapping_status": status}
        if status == "mapped":
            w = ws[0]
            rec["write_kind"] = w[1]
            rec["write_dest"] = w[2]
            rec["write_line"] = w[3]
            sig, fid = S.family_id("\n".join(lines), w)
            rec["family_signature"] = sig
            rec["family_id"] = fid
        sites.append(rec)

    mapped = [s for s in sites if s["mapping_status"] == "mapped"]
    fams = {s["family_id"] for s in mapped}
    manifest = {
        "FROZEN": True, "model_calls": 0, "tchecker_used": False,
        "source": "ARVO-Meta (github.com/n132/ARVO-Meta), OSS-Fuzz reproducible "
                  "vulnerabilities with in-repo fix diffs",
        "preregistration": "PREREGISTER_ARVO.md (committed before first run)",
        "pinned_repo_commit": repo_commit,
        "inclusion": "crash_type starts with {Heap,Stack,Global}-buffer-overflow WRITE "
                     "(sanitizer expression of the frozen write family); Magma-overlap "
                     "projects removed (same frozen union list); C/C++ diff only "
                     "(postcutoff's exact regex); one site per localId, in-source dedup "
                     "by (project, fix_commit) and diff sha256; ENTIRE meta folder "
                     "processed, no early stop.",
        "rule_1_write_site_mapping": "IMPORTED unchanged (diff_hunk_lines + writes_in; "
                                     "unique (kind,dest) across hunks).",
        "rule_2_family_assignment": "IMPORTED unchanged (structural family_id).",
        "exclusions": dict(excl),
        "counts": {
            "sites_after_filters": len(sites),
            "mapping": dict(Counter(s["mapping_status"] for s in sites)),
            "mapped_vulnerable": len(mapped),
            "vulnerable_families": len(fams),
            "family_sizes": dict(Counter(s["family_id"] for s in mapped)),
            "by_project_mapped": dict(Counter(s["project"] for s in mapped)),
            "by_write_kind": dict(Counter(s["write_kind"] for s in mapped)),
            "by_crash_type": dict(Counter(s["crash_type"].split()[0] for s in mapped)),
        },
        "sites": sites,
    }
    outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "study", "arvo",
                        "FROZEN_heldout.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(manifest, open(outp, "w"), indent=2, sort_keys=True)
    print("sites after filters:", len(sites), " exclusions:", dict(excl))
    print("mapping:", dict(Counter(s["mapping_status"] for s in sites)))
    print(f"MAPPED vulnerable sites: {len(mapped)}   FAMILIES (this source alone): {len(fams)}")
    print("by project (top):", Counter(s["project"] for s in mapped).most_common(12))
    print("by write kind:", dict(Counter(s["write_kind"] for s in mapped)))
    print("frozen ->", outp)


if __name__ == "__main__":
    main()
