#!/usr/bin/env python3
"""Exploratory-scan driver: runs the FROZEN scanner-v2 producers (base v1/v2 + capabilities
1-4) against one cpp.json, unmodified. NO producer/capability/rule/route is changed. NO CVE
list is consulted to select or promote findings -- every candidate the producers emit is
reported. Output is grouped by producer / reason / route / file / function, plus (where the
producer supplies it) a physical-write identity, and separated into:
  DETERMINISTIC   -- disposition == deterministic_complete or proven_oversized (the write
                     length/count vs. destination-capacity relationship IS established)
  OPEN_RELATIONSHIP -- relationship_unresolved / capacity_relation_not_established (routes:
                     range_arithmetic_review, semantic_relationship_review)
  MISSING_EVIDENCE -- additional_evidence_required (capacity, base, or resolution absent)
  UNSUPPORTED_REPRESENTATION -- the producer recognized the call/site shape at all but could
                     not resolve identity/binding (e.g. cap3 binding=mismatch/unavailable)
This is a REPORTING tool only -- it does not add sites to any frozen held-out corpus and
makes no accuracy/generalization claim.
"""
import json
import os
import sys
from collections import defaultdict

SCANNER = "/tmp/scanner-defbranch/semantic-bucket-pilot/scanner-v2"
sys.path.insert(0, SCANNER)
import oob_runtime_capacity_v2 as base_v2
import cap_addr_indexed as cap1
import cap_wrapper_summary as cap2
import cap_member_pointer_walk as cap3
import cap_counted_loop_writer as cap4
import cap_write_site_dedup as WSD


def bucket(rec):
    """Bucket a record from ANY producer's own vocabulary (unmodified). Two families:
      - v2-refined / cap1/cap2/cap3/cap4 records: disposition/route (or their _v2_
        prefixed twins on base_v1v2's refined subset) directly say deterministic_complete
        / proven_oversized / relationship_unresolved / additional_evidence_required.
      - base_v1v2 passthrough records (untouched by the v2 refinement -- e.g. a v1 heap
        record, or a v1 abstain v2 couldn't bind a call to): only analysis_status /
        reason_code / uncertainty_bucket are present.
    UNSUPPORTED_REPRESENTATION is the true fallback: the producer recognized SOMETHING
    (it emitted a record) but neither vocabulary tells us evidence is simply missing --
    e.g. cap3's binding=mismatch/unavailable (structural proof unavailable), or a v1
    abstain whose reason isn't the ordinary required_evidence_absent shape."""
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

    if rec.get("binding") in ("mismatch", "unavailable"):
        return "UNSUPPORTED_REPRESENTATION"
    return "UNSUPPORTED_REPRESENTATION"


def _name_to_files(d):
    """function NAME -> set(file). Producer output records carry only the function
    NAME (resolved from fn_id inside each capability module, which does not surface
    it), so file attribution here is a best-effort join, not the full WSD physical-write
    identity (which binds through the raw call/declaration node id, not a name join).
    A name mapping to >1 file is flagged AMBIGUOUS rather than guessed."""
    m = defaultdict(set)
    for f in d.get("functions", []):
        if f.get("name"):
            m[f["name"]].add(f.get("file"))
    return m


def _attach_identity(rec, name_to_files):
    fn = rec.get("function")
    files = name_to_files.get(fn) or set()
    if len(files) == 1:
        rec["file"] = next(iter(files))
    elif len(files) > 1:
        rec["file"] = "AMBIGUOUS(name-collision:%d files)" % len(files)
    else:
        rec["file"] = None
    dest = rec.get("dest") or rec.get("write_dest") or rec.get("sink") or rec.get("callee") or ""
    rec["physical_write_identity_simplified"] = "|".join(
        str(x) for x in (rec.get("file"), fn, rec.get("line"), dest))
    return rec


def run_one(cpp_path, label):
    d_for_names = json.load(open(cpp_path))
    name_to_files = _name_to_files(d_for_names)
    del d_for_names
    findings = []
    # --- base frozen scanner (v1 + v2 stack-capacity refinement) ---
    try:
        out, _tr = base_v2.analyze_operations_v2(cpp_path)
        for r in out:
            r = dict(r)
            r["producer"] = "base_v1v2"
            findings.append(r)
    except Exception as e:
        print(f"  [base_v1v2] EXCEPTION: {e}", file=sys.stderr)

    # --- capability 1: &(base[index]) ---
    try:
        for r in cap1.analyze_addr_indexed(cpp_path):
            r = dict(r)
            r["producer"] = "cap1_addr_indexed"
            r.setdefault("disposition", r.get("disposition"))
            findings.append(r)
    except Exception as e:
        print(f"  [cap1] EXCEPTION: {e}", file=sys.stderr)

    # --- capability 2: transparent wrapper summaries ---
    try:
        ops, _summ = cap2.analyze_wrapper_calls(cpp_path)
        for r in ops:
            r = dict(r)
            r["producer"] = "cap2_wrapper_summary"
            findings.append(r)
    except Exception as e:
        print(f"  [cap2] EXCEPTION: {e}", file=sys.stderr)

    # --- capability 3: advancing-pointer struct-member walks ---
    try:
        for r in cap3.analyze_member_walks(cpp_path):
            r = dict(r)
            r["producer"] = "cap3_member_pointer_walk"
            findings.append(r)
    except Exception as e:
        print(f"  [cap3] EXCEPTION: {e}", file=sys.stderr)

    # --- capability 4: counted-loop writers ---
    try:
        ops, _summ = cap4.analyze_counted_writers(cpp_path)
        for r in ops:
            r = dict(r)
            r["producer"] = "cap4_counted_loop_writer"
            findings.append(r)
    except Exception as e:
        print(f"  [cap4] EXCEPTION: {e}", file=sys.stderr)

    for r in findings:
        r["_bucket"] = bucket(r)
        r["_source_label"] = label
        _attach_identity(r, name_to_files)
    return findings


def main():
    if len(sys.argv) < 2:
        print("usage: run_moz_scan.py <cpp.json> [label]", file=sys.stderr)
        sys.exit(2)
    cpp_path = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else os.path.basename(os.path.dirname(cpp_path))
    findings = run_one(cpp_path, label)

    by_producer = defaultdict(int)
    by_bucket = defaultdict(int)
    by_producer_bucket = defaultdict(lambda: defaultdict(int))
    for r in findings:
        by_producer[r["producer"]] += 1
        by_bucket[r["_bucket"]] += 1
        by_producer_bucket[r["producer"]][r["_bucket"]] += 1

    summary = {
        "label": label,
        "cpp_json": os.path.abspath(cpp_path),
        "total_candidates": len(findings),
        "by_producer": dict(by_producer),
        "by_bucket": dict(by_bucket),
        "by_producer_and_bucket": {k: dict(v) for k, v in by_producer_bucket.items()},
    }
    print(json.dumps(summary, indent=2))

    out_path = cpp_path + ".moz_scan_findings.json"
    json.dump({"summary": summary, "findings": findings}, open(out_path, "w"), indent=2, sort_keys=True, default=str)
    print(f"-> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
