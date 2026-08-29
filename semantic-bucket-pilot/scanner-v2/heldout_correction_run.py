#!/usr/bin/env python3
"""POST-HOC CORRECTION dataset. Replays the held-out population on the ARCHIVED cached CPGs with
the runtime-capacity producer corrected from V1 (heap-only, mistakenly invoked in the original
one-time run) to V2 (declared stack-capacity integration), V2 CANONICAL over V1 with V1 kept as
provenance. Reads cache only (no re-scan, no scanner change). Does NOT overwrite the original raw
run; writes a separate corrected dataset with per-site V1->V2 transition, recognition-set and
disposition comparisons, and hashes.

cap3 (member walk) is excluded from this cache replay because it needs a joern for-structure scan
and recognized 0 labeled sites in the original run; its absence cannot change recognition.
"""
import hashlib, json, os, sys, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
TOOLS = os.path.join(HERE, "..", "..", "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
sys.path.insert(0, TOOLS)
import cap_write_site_dedup as WSD
import oob_runtime_capacity_v2 as RCV2
import cap_addr_indexed as C1, cap_wrapper_summary as C2W, cap_counted_loop_writer as C2L
import cap_decoder_contract as C4
def _L(n):
    s = importlib.util.spec_from_file_location(n, os.path.join(TOOLS, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
CUR = _L("oob_cursor_write_verdict"); IPR = _L("oob_interprocedural_verdict")
V1RC = _L("oob_runtime_capacity_verdict")

CACHE = os.path.join(HERE, "study", "heldout_diagnosis", "cache")
OUT = os.path.join(HERE, "study", "heldout_correction")
EVIDENCE_ABSENT = {"required_evidence_absent", "capacity_of_dest_unresolved",
                   "capacity_of_base_unresolved", "write_count_bound_not_established",
                   "contract_identity_unresolved", "for_structure_unavailable",
                   "decoder_capacity_in_state_object", "write_extent_unresolved",
                   "unknown_allocator_contract", "allocation_overflow_relation_unresolved"}
# Under V2, capacity_relation_not_established means capacity WAS bound, relation unresolved ->
# that is evidence-established / relationship_unresolved, NOT evidence-absent.
RESOLVED = {"deterministic_complete", "proven_oversized"}


def _sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def records(cpp, use_v2):
    """All producer records (cursor, interproc, runtime-capacity V1-or-V2, cap1/2/4). Returns
    list of {producer,function,line,dest,status,reason,route,[v1_provenance]}."""
    out = []
    for pname, m in (("oob_cursor_write_verdict", CUR), ("oob_interprocedural_verdict", IPR)):
        for r in m.analyze_operations(cpp):
            out.append({"producer": pname, "function": r.get("function"), "line": r.get("line"),
                        "dest": r.get("dest"), "status": r.get("analysis_status"),
                        "reason": r.get("reason_code"), "route": r.get("recommended_route")})
    if use_v2:
        v1ops, v2ops, _t = RCV2.analyze_operations_v1_and_v2(cpp)
        v1by = {(r.get("function"), r.get("line"), r.get("dest")): r for r in v1ops}
        for r in v2ops:
            v1 = v1by.get((r.get("function"), r.get("line"), r.get("dest")))
            out.append({"producer": "oob_runtime_capacity_v2", "canonical": "v2",
                        "function": r.get("function"), "line": r.get("line"), "dest": r.get("dest"),
                        "status": r.get("analysis_status"), "reason": r.get("reason_code"),
                        "route": r.get("recommended_route"),
                        "v1_provenance": ({"status": v1.get("analysis_status"),
                                           "reason": v1.get("reason_code")} if v1 else None)})
    else:
        for r in V1RC.analyze_operations(cpp):
            out.append({"producer": "oob_runtime_capacity_verdict", "function": r.get("function"),
                        "line": r.get("line"), "dest": r.get("dest"),
                        "status": r.get("analysis_status"), "reason": r.get("reason_code"),
                        "route": r.get("recommended_route")})
    for r in C1.analyze_addr_indexed(cpp):
        out.append({"producer": "cap1_addr_indexed", "function": r.get("function"),
                    "line": r.get("line"), "dest": r.get("dest"),
                    "status": r.get("disposition"), "reason": r.get("reason"), "route": r.get("route")})
    ops, _ = C2W.analyze_wrapper_calls(cpp)
    for r in ops:
        out.append({"producer": "cap2_wrapper", "function": r.get("function"), "line": r.get("line"),
                    "dest": r.get("dest"), "status": r.get("disposition"), "reason": r.get("reason"),
                    "route": r.get("route")})
    cl = C2L.analyze_counted_writers(cpp); cl = cl[0] if isinstance(cl, tuple) else cl
    for r in cl:
        out.append({"producer": "cap2_counted_loop", "function": r.get("function"),
                    "line": r.get("line"), "dest": r.get("dest"), "status": r.get("disposition"),
                    "reason": r.get("reason"), "route": r.get("route")})
    for r in C4.analyze_decoder_calls(cpp):
        out.append({"producer": "cap4_decoder", "function": r.get("function"), "line": r.get("line"),
                    "dest": r.get("dest"), "status": r.get("disposition"), "reason": r.get("reason"),
                    "route": r.get("route")})
    return out


def at(recs, fn, L, dest):
    rd = WSD._root_ident(dest or "")
    return [r for r in recs if r.get("line") == L and r.get("function") == fn
            and WSD._root_ident(r.get("dest") or "") == rd and rd]


def disp(recs):
    st = {r.get("status") for r in recs}; rs = {r.get("reason") for r in recs}
    if st & RESOLVED:
        return "resolved"
    ev = any(x not in EVIDENCE_ABSENT for x in rs)   # V2 capacity_relation_not_established -> ev
    return "open" if ev else "missing"


def process(orig_rows, tag):
    corrected = []; recog_v1 = recog_v2 = 0; disp_changes = []
    for row in orig_rows:
        r = dict(row)
        sid = row.get("site_id")
        cpp = os.path.join(CACHE, sid + ".cpp.json") if sid else None
        if not (row.get("stage3_labeled_write_mapped") and cpp and os.path.exists(cpp)):
            corrected.append(r); continue
        fn = row.get("func_name"); L = row.get("mapped_line") or row.get("labeled_line")
        dest = row.get("write_dest")
        v1recs = records(cpp, use_v2=False); v2recs = records(cpp, use_v2=True)
        m1 = at(v1recs, fn, L, dest); m2 = at(v2recs, fn, L, dest)
        recog_v1 += bool(m1); recog_v2 += bool(m2)
        r["corrected_recognized_v2"] = bool(m2)
        r["corrected_canonical_records"] = m2
        r["corrected_disposition_v2"] = disp(m2) if m2 else None
        r["original_disposition_v1"] = row.get("stage6_relationship")
        # per-site V1->V2 transition for the runtime-capacity op
        _v1o, _v2o, trans = RCV2.analyze_operations_v1_and_v2(cpp)
        r["v1_v2_transition"] = [t for t in trans if t.get("function") == fn and t.get("line") == L]
        if bool(m1) != bool(m2) or (m1 and m2 and disp(m1) != disp(m2)):
            disp_changes.append({"site": fn, "site_id": sid, "vuln": row.get("is_vulnerable", None),
                                 "v1": disp(m1) if m1 else "unrecognized",
                                 "v2": disp(m2) if m2 else "unrecognized"})
        corrected.append(r)
    return corrected, recog_v1, recog_v2, disp_changes


def main():
    os.makedirs(OUT, exist_ok=True)
    vuln = [json.loads(l) for l in open(os.path.join(HERE, "study", "heldout_run", "raw_sites.jsonl"))]
    neg = [json.loads(l) for l in open(os.path.join(HERE, "study", "heldout_negatives", "raw_negatives.jsonl"))]
    for r in neg:
        r["is_vulnerable"] = False
    cv, v1_v, v2_v, ch_v = process(vuln, "vuln")
    cn, v1_n, v2_n, ch_n = process(neg, "neg")
    with open(os.path.join(OUT, "corrected_vulnerable.jsonl"), "w") as f:
        for r in cv:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(OUT, "corrected_negative.jsonl"), "w") as f:
        for r in cn:
            f.write(json.dumps(r) + "\n")
    # hashes
    cache_files = sorted(os.listdir(CACHE))
    cache_hash = hashlib.sha256("".join(_sha(os.path.join(CACHE, f)) for f in cache_files).encode()).hexdigest()
    summary = {
        "kind": "post_hoc_correction (does NOT overwrite the original one-time run)",
        "corrected_runner_sha256": _sha(os.path.join(HERE, "heldout_run.py")),
        "correction_generator_sha256": _sha(os.path.join(HERE, "heldout_correction_run.py")),
        "cache_dir_merkle_sha256": cache_hash, "cache_cpp_files": len(cache_files),
        "inputs_sha256": {
            "original_raw_sites": _sha(os.path.join(HERE, "study", "heldout_run", "raw_sites.jsonl")),
            "original_raw_negatives": _sha(os.path.join(HERE, "study", "heldout_negatives", "raw_negatives.jsonl")),
            "pooled_manifest": _sha(os.path.join(HERE, "study", "pooled", "FROZEN_heldout_pooled.json"))},
        "population": {"vulnerable_rows": len(cv), "negative_rows": len(cn)},
        "recognition_set_comparison": {
            "vulnerable": {"v1_recognized_mapped": v1_v, "v2_recognized_mapped": v2_v,
                           "invariant": v1_v == v2_v},
            "negative": {"v1_recognized_mapped": v1_n, "v2_recognized_mapped": v2_n,
                         "invariant": v1_n == v2_n}},
        "disposition_changes": {"vulnerable": ch_v, "negative": ch_n}}
    json.dump(summary, open(os.path.join(OUT, "CORRECTED_SUMMARY.json"), "w"), indent=2, sort_keys=True)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
