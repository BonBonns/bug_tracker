#!/usr/bin/env python3
"""Exploratory-scan driver v2 -- corrects the v1 driver's capability mislabeling and adds
module-provenance capture + a proper cross-producer dedup pass.

CORRECTION (reconciling the pilot's own provenance):
  - `cap_counted_loop_writer.py` is NOT "Capability 4". Per
    `CAP2_CAP3_BOUNDARY_FROZEN.md` at 8b77705 (frozen BEFORE capability 3 began): Capability
    2 is TWO models, both attribution=call_site_summary -- the delegation wrapper
    (`cap_wrapper_summary.py`) and the counted-writer/loop
    (`cap_counted_loop_writer.py`). Capability 3 is `cap_member_pointer_walk.py`
    (attribution=direct). Capability 4 (`cap_decoder_contract.py`, external decoder
    contracts) does not exist at 8b77705 at all -- introduced later, at commit 111b653 /
    6eb1f42 on the SAME branch, strictly after this pilot's base commit. `git ls-tree
    8b77705` confirms its absence; `git merge-base --is-ancestor 8b77705 6eb1f42` confirms
    6eb1f42 is a strict descendant. The v1 pilot report's "capabilities 1-4" label was
    wrong -- it ran capability 1, both capability-2 models, and capability 3. Relabeled
    throughout this file and PILOT_REPORT.md's addendum.

PROVENANCE: every producer module's __file__ + sha256 is recorded so contamination
(scenario 3: an unintended module shadowing another on PYTHONPATH) is falsifiable, not
asserted. Run with PYTHONPATH explicitly cleared from a FRESH worktree pinned at 8b77705
(not the exploratory branch's own working copy, which also carries this repo's added
moz-exploratory-scan/ directory -- irrelevant to imports, but a clean worktree removes any
doubt).

DEDUP: cap2's two models and cap3 carry the frozen `cap_write_site_dedup` physical-write
identity (cap2 via `underlying_write`; cap3's per-walk `member_writes` list is each
individually a WSD identity -- flattened here into one pseudo-record per constituent
write, tagged attribution=direct, EXACTLY as cap3's own analysis already computed them,
not re-derived). Capability 1 and the base v1/v2 cursor producer do NOT carry a WSD
identity anywhere in the frozen codebase (cap1 never imports cap_write_site_dedup; the
base producer predates it) -- reported as raw producer-record counts only, explicitly
NOT deduplicated against cap2/cap3, rather than fabricating an identity scheme for them
(that would be adding logic to a frozen producer's semantics, which this driver must not
do).
"""
import hashlib
import json
import os
import sys
from collections import defaultdict

SCANNER = os.environ["SCANNER_DIR"]  # required, no default -- caller must state which checkout
assert os.path.isdir(SCANNER), f"SCANNER_DIR does not exist: {SCANNER}"
sys.path.insert(0, SCANNER)
import oob_runtime_capacity_v2 as base_v2
import cap_addr_indexed as cap1
import cap_wrapper_summary as cap2a
import cap_counted_loop_writer as cap2b
import cap_member_pointer_walk as cap3
import cap_write_site_dedup as WSD

PRODUCER_MODULES = {
    "base_v1v2": base_v2,
    "cap1_addr_indexed": cap1,
    "cap2a_wrapper_summary": cap2a,
    "cap2b_counted_loop_writer": cap2b,
    "cap3_member_pointer_walk": cap3,
    "cap_write_site_dedup": WSD,
}


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def module_provenance():
    """__file__ + sha256 for every producer module actually bound in THIS process, at
    call time -- not asserted, read back from the live module objects."""
    prov = {}
    for label, mod in PRODUCER_MODULES.items():
        f = getattr(mod, "__file__", None)
        prov[label] = {
            "module_file": f,
            "sha256": _sha256_file(f) if f and os.path.exists(f) else None,
            "under_scanner_dir": bool(f and os.path.realpath(f).startswith(os.path.realpath(SCANNER) + os.sep)),
        }
    return prov


def bucket(rec):
    disp = rec.get("_v2_disposition") or rec.get("disposition")
    route = rec.get("_v2_route") or rec.get("route")
    if disp in ("deterministic_complete", "proven_oversized"):
        return "DETERMINISTIC"
    if disp == "relationship_unresolved" or route in ("range_arithmetic_review", "semantic_relationship_review"):
        return "OPEN_RELATIONSHIP"
    if route == "additional_evidence_required":
        return "MISSING_EVIDENCE"
    status = rec.get("analysis_status")
    reason = rec.get("primary_reason_code") or rec.get("reason_code")
    ubucket = rec.get("uncertainty_bucket")
    if status == "deterministic_complete":
        return "DETERMINISTIC"
    if status == "open_candidate" and ubucket == "relationship_unresolved":
        return "OPEN_RELATIONSHIP"
    if status == "abstained" and reason == "required_evidence_absent":
        return "MISSING_EVIDENCE"
    return "UNSUPPORTED_REPRESENTATION"


def _name_to_files(d):
    m = defaultdict(set)
    for f in d.get("functions", []):
        if f.get("name"):
            m[f["name"]].add(f.get("file"))
    return m


def _attach_identity(rec, name_to_files):
    fn = rec.get("function")
    files = name_to_files.get(fn) or set()
    rec["file"] = next(iter(files)) if len(files) == 1 else (
        f"AMBIGUOUS(name-collision:{len(files)} files)" if files else None)
    dest = rec.get("dest") or rec.get("write_dest") or rec.get("sink") or rec.get("callee") or ""
    rec["physical_write_identity_simplified"] = "|".join(
        str(x) for x in (rec.get("file"), fn, rec.get("line"), dest))
    return rec


def run_one(cpp_path, label):
    d = json.load(open(cpp_path))
    name_to_files = _name_to_files(d)
    del d
    findings = []

    try:
        out, _tr = base_v2.analyze_operations_v2(cpp_path)
        for r in out:
            r = dict(r); r["producer"] = "base_v1v2"; r["real_capability"] = "0_frozen_cursor_producer"
            findings.append(r)
    except Exception as e:
        print(f"  [base_v1v2] EXCEPTION: {e}", file=sys.stderr)

    try:
        for r in cap1.analyze_addr_indexed(cpp_path):
            r = dict(r); r["producer"] = "cap1_addr_indexed"; r["real_capability"] = "1"
            findings.append(r)
    except Exception as e:
        print(f"  [cap1] EXCEPTION: {e}", file=sys.stderr)

    cap2a_ops = []
    try:
        ops, _summ = cap2a.analyze_wrapper_calls(cpp_path)
        for r in ops:
            r = dict(r); r["producer"] = "cap2a_wrapper_summary"; r["real_capability"] = "2 (delegation-wrapper model)"
            findings.append(r); cap2a_ops.append(r)
    except Exception as e:
        print(f"  [cap2a] EXCEPTION: {e}", file=sys.stderr)

    cap2b_ops = []
    try:
        ops, _summ = cap2b.analyze_counted_writers(cpp_path)
        for r in ops:
            r = dict(r); r["producer"] = "cap2b_counted_loop_writer"; r["real_capability"] = "2 (counted-loop-writer model)"
            findings.append(r); cap2b_ops.append(r)
    except Exception as e:
        print(f"  [cap2b] EXCEPTION: {e}", file=sys.stderr)

    cap3_ops = []
    try:
        for r in cap3.analyze_member_walks(cpp_path):
            r = dict(r); r["producer"] = "cap3_member_pointer_walk"; r["real_capability"] = "3"
            findings.append(r); cap3_ops.append(r)
    except Exception as e:
        print(f"  [cap3] EXCEPTION: {e}", file=sys.stderr)

    for r in findings:
        r["_bucket"] = bucket(r)
        r["_source_label"] = label
        _attach_identity(r, name_to_files)

    # ---- dedup pass, ONLY over producers that carry a frozen WSD identity -----------------
    # cap2a/cap2b: identity IS `underlying_write` (already WSD.physical_write_identity()).
    # cap3: identity is NOT on the top-level per-walk record (it aggregates N member writes
    # per cursor family) -- flatten `member_writes` (already individually
    # WSD.physical_write_identity() results, computed by cap3's OWN analysis, not re-derived
    # here) into one pseudo-record per constituent physical write.
    dedup_input = []
    for r in cap2a_ops + cap2b_ops:
        dedup_input.append({"attribution": "call_site_summary", "producer": r["producer"],
                            "underlying_write": r.get("underlying_write"),
                            "underlying_write_node_id": r.get("underlying_write_node_id"),
                            "source_record": r})
    for r in cap3_ops:
        for mw in (r.get("member_writes") or []):
            dedup_input.append({"attribution": "direct", "producer": "cap3_member_pointer_walk",
                                "identity": mw, "source_record": r})
    verifiable = [x for x in dedup_input if WSD.is_verifiable(x)]
    unverifiable = [x for x in dedup_input if not WSD.is_verifiable(x)]
    deduped = WSD.dedup(verifiable) if verifiable else []

    dedup_summary = {
        "scope": "cap2a + cap2b + cap3 ONLY (the only producers carrying a frozen "
                 "WSD physical-write identity); cap1 and base_v1v2 are NOT identity-"
                 "integrated anywhere in the frozen codebase and are excluded from this "
                 "count, not silently folded in as if deduplicated",
        "raw_records_in_scope": len(dedup_input),
        "verifiable": len(verifiable),
        "unverifiable_never_merged": len(unverifiable),
        "unique_physical_write_operations": len(deduped),
    }

    return findings, dedup_summary, deduped


def main():
    cpp_path = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else os.path.basename(os.path.dirname(cpp_path))
    prov = module_provenance()
    findings, dedup_summary, deduped_ops = run_one(cpp_path, label)

    by_producer = defaultdict(int)
    by_bucket = defaultdict(int)
    by_producer_bucket = defaultdict(lambda: defaultdict(int))
    by_real_capability = defaultdict(int)
    for r in findings:
        by_producer[r["producer"]] += 1
        by_bucket[r["_bucket"]] += 1
        by_producer_bucket[r["producer"]][r["_bucket"]] += 1
        by_real_capability[r["real_capability"]] += 1

    summary = {
        "label": label,
        "cpp_json": os.path.abspath(cpp_path),
        "SCANNER_DIR": SCANNER,
        "total_raw_producer_records": len(findings),
        "by_producer": dict(by_producer),
        "by_real_capability": dict(by_real_capability),
        "by_bucket": dict(by_bucket),
        "by_producer_and_bucket": {k: dict(v) for k, v in by_producer_bucket.items()},
        "dedup": dedup_summary,
        "module_provenance": prov,
    }
    print(json.dumps(summary, indent=2))

    out_path = cpp_path + ".moz_scan_v2_findings.json"
    json.dump({"summary": summary, "findings": findings, "deduped_operations": deduped_ops},
              open(out_path, "w"), indent=2, sort_keys=True, default=str)
    print(f"-> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
