#!/usr/bin/env python3
"""Freeze the Big-Vul (MSR'20) slice of the held-out confirmatory corpus, per
PREREGISTER_BIGVUL.md (committed before this script's first run). NO model calls,
NO TChecker, NO manual per-site interpretation.

RULE 1 and RULE 2 are IMPORTED from the frozen modules (secvuleval_freeze.writes_in /
family_id, postcutoff_freeze.diff_hunk_lines) and applied unchanged to each site's
concatenated C/C++ fix-diff patches. The ENTIRE dataset is processed; no early stop.

Usage: bigvul_freeze.py <all_c_cpp_release2.0.csv> <pinned_repo_commit>
"""
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secvuleval_freeze as S   # frozen writes_in + family_id
import postcutoff_freeze as P   # frozen diff_hunk_lines + WRITE_CWE numbers

WRITE_CWE = {f"CWE-{n}" for n in P.WRITE_CWE}
MAGMA_NAMES = {p.lower() for p in S.MAGMA_PROJECTS} | \
              {r.split("/")[-1].lower() for r in P.MAGMA_REPOS} | \
              {r.split("/")[0].lower() for r in P.MAGMA_REPOS}
C_CPP_FILE = re.compile(r"\.(c|cc|cpp|cxx|h|hpp)$", re.I)
SEP = "<_**next**_>"


def c_cpp_patch(files_changed):
    """Concatenated unified-diff patches of the C/C++ files in one row."""
    parts, bad = [], 0
    for chunk in files_changed.split(SEP):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            f = json.loads(chunk)
        except Exception:
            bad += 1
            continue
        if C_CPP_FILE.search(f.get("filename") or "") and f.get("patch"):
            parts.append(f["patch"])
    return "\n".join(parts), bad


def main():
    csv_path, repo_commit = sys.argv[1], sys.argv[2]
    csv.field_size_limit(sys.maxsize)
    raw_sha = hashlib.sha256(open(csv_path, "rb").read()).hexdigest()

    excl = Counter()
    sites, seen = [], set()
    unparseable_file_objs = 0
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            cwe = (row.get("cwe_id") or "").strip()
            if cwe not in WRITE_CWE:
                excl["not_write_cwe"] += 1
                continue
            proj = (row.get("project") or "").strip()
            if proj.lower() in MAGMA_NAMES:
                excl["magma_overlap_project"] += 1
                continue
            key = (row.get("cve_id"), row.get("commit_id"))
            if key in seen:
                excl["duplicate_cve_commit"] += 1
                continue
            seen.add(key)
            diff, bad = c_cpp_patch(row.get("files_changed") or "")
            unparseable_file_objs += bad
            if not diff:
                excl["not_c_cpp_or_no_patch"] += 1
                continue
            lines = P.diff_hunk_lines(diff)
            ws = S.writes_in(lines)
            if not ws:
                status = "no_write_found"
            else:
                uniq = {(w[1], w[2]) for w in ws}   # frozen: unique (kind, dest) across hunk
                status = "mapped" if len(uniq) == 1 else "ambiguous"
            rec = {"cve": row.get("cve_id"), "commit_id": row.get("commit_id"),
                   "project": proj, "cwe": cwe,
                   "publish_date": row.get("publish_date"),
                   "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
                   "mapping_status": status}
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
        "source": "Big-Vul MSR'20 commit-level release "
                  "(github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset)",
        "preregistration": "PREREGISTER_BIGVUL.md (committed before first run)",
        "pinned_repo_commit": repo_commit,
        "csv_sha256": raw_sha,
        "rule_1_write_site_mapping": "IMPORTED unchanged: postcutoff diff variant -- "
                                     "diff_hunk_lines + writes_in; mapped iff a UNIQUE "
                                     "(write_kind, dest) exists across the C/C++ fix-diff "
                                     "hunks; ambiguous/no_write_found otherwise; only "
                                     "mapped sites score.",
        "rule_2_family_assignment": "IMPORTED unchanged: family_id = hash(write_kind | "
                                    "dest_shape | length_shape) from source structure "
                                    "only; frozen now, never recomputed.",
        "inclusion": "cwe_id in write family {787,122,120,121,124,680,805,806}; "
                     "Magma-overlap projects removed (union of the two frozen lists); "
                     "C/C++ file patches only; one site per (cve_id, commit_id); "
                     "ENTIRE dataset processed, no early stop.",
        "unparseable_file_objects": unparseable_file_objs,
        "exclusions": dict(excl),
        "counts": {
            "sites_after_filters": len(sites),
            "mapping": dict(Counter(s["mapping_status"] for s in sites)),
            "mapped_vulnerable": len(mapped),
            "vulnerable_families": len(fams),
            "family_sizes": dict(Counter(s["family_id"] for s in mapped)),
            "by_project_mapped": dict(Counter(s["project"] for s in mapped)),
            "by_write_kind": dict(Counter(s["write_kind"] for s in mapped)),
        },
        "sites": sites,
    }
    outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "study", "bigvul",
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
