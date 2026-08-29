#!/usr/bin/env python3
"""SPECIFICITY / SOUNDNESS run on the separately-preserved 101 NON-VULNERABLE mapped SecVulEval
sites, with the UNCHANGED frozen scanner (capabilities 1-4 + frozen producers). This is a
DISTINCT frozen measurement from the 258 vulnerable corpus (which is now consumed). It measures,
on labeled NON-vulnerable write sites: (a) how many the scanner recognizes, and (b) among
recognized sites, how many it PROMOTES to a verdict -- `proven_oversized` = an UNSUPPORTED
VULNERABILITY PROMOTION on non-vulnerable code, `deterministic_complete` = a safe promotion --
versus abstains. It does NOT yield conventional accuracy (the scanner does not emit comparable
safe/vulnerable conclusions on most sites); it completes the soundness picture.

Reuses the UNCHANGED heldout_run.py functions (same scanner, same identity reconciliation).
Archive raw before summarizing; run the frozen scanner once.

Usage: JOERN=/tmp/joern-cli/joern REPO=/home/user/bug_tracker python3 heldout_negatives_run.py <outdir>
"""
import gzip, hashlib, json, os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import heldout_run as HR   # UNCHANGED scanner harness functions

STUDY = os.path.join(HERE, "study")
GZ = ("/tmp/claude-0/-home-user-bug-tracker/0fd64c6d-7e3d-554b-9af8-02d9e6597995/"
      "scratchpad/secvuleval_full.jsonl.gz")
PROMOTE_SAFE = {"deterministic_complete"}
PROMOTE_VULN = {"proven_oversized"}


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/heldout_neg"
    os.makedirs(outdir, exist_ok=True)
    man = json.load(open(os.path.join(STUDY, "secvuleval_full", "FROZEN_heldout.json")))
    nv = [s for s in man["sites"]
          if s.get("mapping_status") == "mapped" and s.get("is_vulnerable") is False]
    assert len(nv) == 101, len(nv)
    bodies = {}
    for ln in gzip.open(GZ, "rt"):
        o = json.loads(ln)
        h = hashlib.sha256(o["func_body"].encode()).hexdigest()
        if h not in bodies:
            bodies[h] = o["func_body"]

    raw = open(os.path.join(outdir, "raw_negatives.jsonl"), "w")
    for s in nv:
        h = s["func_body_sha256"]
        row = {"site_id": s["site_id"], "func_name": s.get("func_name"),
               "family_id": s.get("family_id"), "write_kind": s.get("write_kind"),
               "write_dest": s.get("write_dest"), "write_line": s.get("write_line"),
               "is_vulnerable": False,
               "analysis_mode": "frozen_function_level_source_packet"}
        body = bodies.get(h)
        if body is None or hashlib.sha256(body.encode()).hexdigest() != h:
            row.update(stage1_source_available=False,
                       pipeline_attrition="body_missing_or_sha_mismatch")
            raw.write(json.dumps(row) + "\n"); continue
        row["stage1_source_available"] = True
        work = tempfile.mkdtemp()
        open(os.path.join(work, "body.c"), "w").write(body)
        out = os.path.join(work, "out")
        cpp, log = HR.scan(work, out)
        if cpp is None:
            row.update(stage2_build_parse_ok=False, pipeline_attrition="build_or_parse_failed")
            raw.write(json.dumps(row) + "\n"); continue
        row["stage2_build_parse_ok"] = True
        body_lines = body.splitlines()
        mapped, L, mdetail = HR.map_labeled_write(body_lines, cpp, s.get("write_line"),
                                                  s.get("write_dest"))
        row.update(stage3_labeled_write_mapped=mapped, mapped_line=L, map_detail=mdetail)
        recs = HR.recognized_records(cpp)
        recon = HR.reconcile_identity(cpp, recs)
        row["identity_reconciliation"] = {
            k: recon[k] for k in ("raw_recognized_records", "identity_bearing_records",
                                  "unique_physical_operations", "identity_unverifiable_records")}
        row["distinct_recognized_ops"] = (recon["unique_physical_operations"]
                                          + recon["identity_unverifiable_records"])
        # BODY-LEVEL disposition tally across ALL recognized writes in this non-vulnerable body
        # (a promoted overflow ANYWHERE in a non-vulnerable body is a candidate false positive).
        from collections import Counter as _C
        bd = _C(r.get("status") for r in recs if not r.get("error"))
        row["body_dispositions"] = dict(bd)
        row["body_proven_oversized_records"] = bd.get("proven_oversized", 0)
        row["body_deterministic_complete_records"] = bd.get("deterministic_complete", 0)
        if not mapped:
            row["pipeline_attrition"] = "labeled_write_not_mapped"
            raw.write(json.dumps(row) + "\n"); continue
        recog, matched, line_only = HR.recognition_at(recs, {s.get("func_name")}, L,
                                                      s.get("write_dest"))
        row["stage4_recognized"] = recog
        row["matched_records"] = matched
        if recog:
            statuses = {m.get("status") for m in matched}
            # SPECIFICITY signal at the labeled non-vulnerable site:
            row["promotion_vulnerability_unsupported"] = bool(statuses & PROMOTE_VULN)
            row["promotion_safe"] = bool(statuses & PROMOTE_SAFE)
            row["abstained"] = not (statuses & (PROMOTE_VULN | PROMOTE_SAFE))
            row["matched_statuses"] = sorted(x for x in statuses if x)
        raw.write(json.dumps(row) + "\n")
        raw.flush()
    raw.close()
    print("RAW_WRITTEN", os.path.join(outdir, "raw_negatives.jsonl"), "n", len(nv))


if __name__ == "__main__":
    main()
