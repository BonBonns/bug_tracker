#!/usr/bin/env python3
"""Freeze the held-out confirmatory corpus from PostCutoff-CVE (NO model calls, NO TChecker,
NO manual per-site interpretation). SecVulEval's full set is HuggingFace-blocked in this
environment; PostCutoff-CVE is git-reachable, ships the real fix diffs in-repo (identifiers
intact, only paths blinded), is hunk-labeled and time-sliced (post-2025 cutoffs = genuinely
held out), and is much larger for the write-overflow property.

Same two deterministic rules as secvuleval_freeze.py, applied to the fix diff:
  RULE 1 exact write-site mapping: map the security-fix hunk to a UNIQUE destination write
         within the diff; mapped / ambiguous / no_write_found; only mapped sites score.
  RULE 2 family assignment: family_id = hash(write_kind | dest_shape | length_shape) from
         source structure only; frozen now, never recomputed after any scanner output.

Usage: postcutoff_freeze.py <pccve_dir> <repo_commit>
"""
import hashlib
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secvuleval_freeze as S   # reuse the frozen write-detection + family logic

WRITE_CWE = {787, 122, 120, 121, 124, 680, 806, 805}   # destination-capacity WRITE family
READ_CWE = {125, 126, 127}                              # excluded (reads)
MAGMA_REPOS = {"openssl/openssl", "pnggroup/libpng", "libpng/libpng", "the-tcpdump-group/libpcap"}
# note: wolfssl/imagemagick/zephyr/freerdp/libarchive/... are NOT Magma targets


def diff_hunk_lines(diff):
    """Post-fix + context lines of the fix diff (the localized vulnerable region), as plain
    source text for write detection. '-' (removed) lines are included too: the vulnerable
    pre-fix write often lives there."""
    out = []
    for l in diff.splitlines():
        if l[:3] in ("+++", "---") or l.startswith("@@") or l.startswith("diff ") or l.startswith("index "):
            continue
        if l[:1] in ("+", "-", " "):
            out.append(l[1:])
    return out


def main():
    d, commit = sys.argv[1], sys.argv[2]
    idx = {json.loads(l)["benchmark_id"]: json.loads(l) for l in open(f"{d}/data/sample_index.jsonl")}
    bi_raw = open(f"{d}/data/blind_inputs.jsonl", "rb").read()
    bi = {json.loads(l)["benchmark_id"]: json.loads(l) for l in bi_raw.splitlines()}

    excl = Counter()
    sites = []
    for cid, r in idx.items():
        cwes = set(r["strata"].get("cwe_ids") or [])
        repo = r["repository"]["canonical_id"]
        if r["binary_label"] != "vulnerability_fix":
            excl["non_vulnerability_fix"] += 1; continue
        if not (cwes & WRITE_CWE):
            excl["not_write_cwe"] += 1; continue
        if repo in MAGMA_REPOS:
            excl["magma_overlap_repo"] += 1; continue
        diff = bi.get(cid, {}).get("diff", "")
        # C/C++ only: the fix touches a .c/.cpp/.cc/.h file
        if not re.search(r"\.(c|cc|cpp|cxx|h|hpp)\b", diff):
            excl["not_c_cpp"] += 1; continue
        lines = diff_hunk_lines(diff)
        # COMMENT-R01 (see secvuleval_freeze.strip_comments): write-detection runs on
        # comment-stripped text; family_id below still uses the original `lines`/`body`.
        ws = S.writes_in(S.strip_comments(lines))
        if not ws:
            status = "no_write_found"
        else:
            uniq = {(w[1], w[2]) for w in ws}          # (kind, dest) unique across the hunk
            status = "mapped" if len(uniq) == 1 else "ambiguous"
        rec = {"benchmark_id": cid, "repository": repo,
               "cve": (r["identifiers"].get("cve_id") or (r["identifiers"].get("cve_ids") or [None])[0]),
               "cwe_ids": sorted(cwes), "binary_label": r["binary_label"],
               "time_band": r.get("time_band"),
               "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
               "mapping_status": status}
        if status == "mapped":
            w = ws[0]
            rec["write_kind"] = w[1]; rec["write_dest"] = w[2]; rec["write_line"] = w[3]
            body = "\n".join(lines)
            sig, fid = S.family_id(body, w)
            rec["family_signature"] = sig; rec["family_id"] = fid
        sites.append(rec)

    mapped = [s for s in sites if s["mapping_status"] == "mapped"]
    fams = {s["family_id"] for s in mapped}
    manifest = {
        "FROZEN": True, "model_calls": 0, "tchecker_used": False,
        "source": "PostCutoff-CVE v1.0.0 (github.com/20000419/postcutoff-cve-dataset)",
        "why_this_source": "SecVulEval full set is HuggingFace-blocked in this environment (403); "
                           "PostCutoff-CVE is git-reachable, ships real fix diffs in-repo (code intact, "
                           "only paths blinded), hunk-labeled, and time-sliced post-2025 cutoffs so it "
                           "is genuinely held out. The 44-site SecVulEval freeze remains a pilot.",
        "pinned_repo_commit": commit,
        "blind_inputs_sha256": hashlib.sha256(bi_raw).hexdigest(),
        "zenodo_release_sha256": "2446956911b943a58fcdffd3f8be3b63fec545109d870ddc1ec2818b43e95872",
        "rule_1_write_site_mapping": "deterministic: map the security-fix diff hunk to a UNIQUE "
                                     "destination write (copy sink / index / deref) across the hunk; "
                                     "mapped / ambiguous / no_write_found; only mapped sites score.",
        "rule_2_family_assignment": "family_id = hash(write_kind | dest_shape | length_shape) from "
                                    "source structure only; frozen now, never recomputed after "
                                    "scanner outputs are seen.",
        "inclusion": "binary_label==vulnerability_fix; CWE in write-family {787,122,120,121,124,680,805,806}; "
                     "exclude read CWEs; remove Magma-overlap repos; C/C++ diff only.",
        "exclusions": dict(excl),
        "counts": {
            "sites_after_filters": len(sites),
            "mapping": dict(Counter(s["mapping_status"] for s in sites)),
            "mapped_vulnerable": len(mapped),
            "vulnerable_families": len(fams),
            "family_sizes": dict(Counter(s["family_id"] for s in mapped)),
            "by_repo_mapped": dict(Counter(s["repository"] for s in mapped)),
            "by_write_kind": dict(Counter(s["write_kind"] for s in mapped)),
        },
        "twelve_vuln_family_gate": {"gate": 12, "vulnerable_families": len(fams), "meets_gate": len(fams) >= 12},
        "confirmatory_protocol": "Run ALL frozen capabilities once on the mapped sites; score exact-site "
                                 "recognition/evidence/route against the external labels. No capability "
                                 "designed or tuned using any result from this corpus. Yields NOT inspected.",
        "sites": sites,
    }
    outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "study", "postcutoff",
                        "FROZEN_heldout.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(manifest, open(outp, "w"), indent=2, sort_keys=True)
    print("sites after filters:", len(sites), " exclusions:", dict(excl))
    print("mapping:", dict(Counter(s["mapping_status"] for s in sites)))
    print(f"MAPPED vulnerable sites: {len(mapped)}   VULNERABLE FAMILIES: {len(fams)}  "
          f"(12-gate: {'MEETS' if len(fams) >= 12 else 'BELOW'})")
    print("by repo:", dict(Counter(s["repository"] for s in mapped)))
    print("by write kind:", dict(Counter(s["write_kind"] for s in mapped)))
    print("family signatures:", sorted({s["family_signature"] for s in mapped}))
    print("frozen ->", outp)


if __name__ == "__main__":
    main()
