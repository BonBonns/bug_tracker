#!/usr/bin/env python3
"""ONE-TIME held-out confirmatory run (Capability 1-4 + frozen producers) over the frozen
pooled corpus. VULNERABLE-ONLY: measures vulnerable-site recognition/recall & coverage, NOT
precision/FPR. Pipeline attrition (source/build/mapping) is kept SEPARATE from scanner misses.
Producer/capability output is deduplicated through the frozen physical-write identity
(cap_write_site_dedup), preserving every producer's provenance. Raw per-site rows are archived
BEFORE any summary is computed. No capability code is changed by this run.

Usage: JOERN=/tmp/joern-cli/joern REPO=/home/user/bug_tracker python3 heldout_run.py <outdir> [limit]
"""
import gzip, hashlib, importlib.util, json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
TOOLS = os.path.join(HERE, "..", "..", "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
sys.path.insert(0, TOOLS)
STUDY = os.path.join(HERE, "study")
GZ = ("/tmp/claude-0/-home-user-bug-tracker/0fd64c6d-7e3d-554b-9af8-02d9e6597995/"
      "scratchpad/secvuleval_full.jsonl.gz")

import cap_write_site_dedup as WSD
import cap_addr_indexed as C1
import cap_wrapper_summary as C2W
import cap_counted_loop_writer as C2L
import cap_member_pointer_walk as C3
import cap_decoder_contract as C4


def _load(name):
    s = importlib.util.spec_from_file_location(name, os.path.join(TOOLS, name + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


PROD = {n: _load(n) for n in ("oob_cursor_write_verdict", "oob_runtime_capacity_verdict",
                              "oob_interprocedural_verdict")}

# reasons/dispositions that mean the required capacity/contract EVIDENCE was NOT established
EVIDENCE_ABSENT = {
    "required_evidence_absent", "capacity_of_dest_unresolved", "capacity_of_base_unresolved",
    "capacity_relation_not_established", "write_count_bound_not_established",
    "contract_identity_unresolved", "contract_version_unresolved",
    "contract_build_fingerprint_mismatch", "for_structure_unavailable",
    "for_structure_cpp_cpg_mismatch", "decoder_capacity_in_state_object",
    "write_extent_unresolved", "unknown_allocator_contract",
    "allocation_overflow_relation_unresolved",
}
RESOLVED = {"deterministic_complete", "proven_oversized"}
OPEN = {"open_candidate", "relationship_unresolved"}


def _norm(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def scan(srcdir, out):
    r = subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                       capture_output=True, text=True)
    cpp = os.path.join(out, "cpp.json")
    return (cpp if os.path.exists(cpp) else None), (r.stdout + r.stderr)


def recognized_records(cpp):
    """Every recognized physical-write record from the frozen producers + capabilities 1-4,
    normalized to {producer, function, line, dest, status, reason, route}. status/reason feed
    the evidence + relationship stages."""
    out = []
    for pname, m in PROD.items():
        try:
            for r in m.analyze_operations(cpp):
                out.append({"producer": pname, "function": r.get("function"),
                            "line": r.get("line"), "dest": r.get("dest"),
                            "status": r.get("analysis_status"), "reason": r.get("reason_code"),
                            "route": r.get("recommended_route")})
        except Exception as e:
            out.append({"producer": pname, "error": str(e)})
    try:
        for r in C1.analyze_addr_indexed(cpp):
            out.append({"producer": "cap1_addr_indexed", "function": r.get("function"),
                        "line": r.get("line"), "dest": r.get("dest"),
                        "status": r.get("disposition"), "reason": r.get("reason"),
                        "route": r.get("route")})
    except Exception as e:
        out.append({"producer": "cap1_addr_indexed", "error": str(e)})
    try:
        ops, _ = C2W.analyze_wrapper_calls(cpp)
        for r in ops:
            out.append({"producer": "cap2_wrapper", "function": r.get("function"),
                        "line": r.get("line"), "dest": r.get("dest"),
                        "status": r.get("disposition"), "reason": r.get("reason"),
                        "route": r.get("route")})
    except Exception as e:
        out.append({"producer": "cap2_wrapper", "error": str(e)})
    try:
        cl = C2L.analyze_counted_writers(cpp)
        for r in (cl[0] if isinstance(cl, tuple) else cl):   # returns (ops, summaries)
            out.append({"producer": "cap2_counted_loop", "function": r.get("function"),
                        "line": r.get("line"), "dest": r.get("dest"),
                        "status": r.get("disposition"), "reason": r.get("reason"),
                        "route": r.get("route")})
    except Exception as e:
        out.append({"producer": "cap2_counted_loop", "error": str(e)})
    try:
        for r in C3.analyze_member_walks(cpp):
            out.append({"producer": "cap3_member_walk", "function": r.get("function"),
                        "line": r.get("line"), "dest": r.get("cursor"),
                        "status": r.get("disposition"), "reason": r.get("reason"),
                        "route": r.get("route"), "member_writes": r.get("member_write_nodes")})
    except Exception as e:
        out.append({"producer": "cap3_member_walk", "error": str(e)})
    try:
        # no scan-bound build attestation for held-out third-party code -> cap4 recognizes the
        # decoder call SHAPE but leaves contract identity unresolved (correct, conservative).
        for r in C4.analyze_decoder_calls(cpp):
            out.append({"producer": "cap4_decoder", "function": r.get("function"),
                        "line": r.get("line"), "dest": r.get("dest"),
                        "status": r.get("disposition"), "reason": r.get("reason"),
                        "route": r.get("route")})
    except Exception as e:
        out.append({"producer": "cap4_decoder", "error": str(e)})
    return out


def reconcile_identity(cpp, recs):
    """Reconcile producer output through the frozen physical-write identity and ASSERT the
    monotone chain
        raw recognized records  >=  identity-bearing records  >=  unique physical operations.
    For each recognized record, an identity is computed from the MATCHED CPG write node
    (cap1/cursor producers do not natively carry the shared identity); a record with no
    matched write node is marked identity_unverifiable and is NEVER merged with another (each
    gets its own monotonic op). Every producer's provenance is preserved."""
    d = json.load(open(cpp))
    index = WSD.build_index(d)
    by_fl = {}
    for c in d.get("calls", []):
        if WSD.write_target(c) is not None:
            by_fl.setdefault((index["funcs"].get(c.get("enclosing_function_id"), {}).get("name"),
                              c.get("line")), []).append(c)
    raw = [r for r in recs if not r.get("error")]
    id_groups = {}          # frozen-identity key -> op (identity-bearing; merged by identity)
    unverifiable = []       # each its own op, never merged
    identity_bearing = 0
    for r in raw:
        fn, ln, dest = r.get("function"), r.get("line"), r.get("dest")
        rd = WSD._root_ident(dest or "")
        node = None
        for c in by_fl.get((fn, ln), []):
            if rd and WSD._root_ident(WSD.write_target(c) or "") == rd:
                node = c
                break
        prov = {"producer": r["producer"], "status": r.get("status"),
                "reason": r.get("reason"), "route": r.get("route")}
        if node is not None:
            ident, _ = WSD.physical_write_identity(node, index)
            key = str(WSD.identity_key({"identity": ident}))
            g = id_groups.setdefault(key, {"identity_key": key, "function": fn, "line": ln,
                                           "dest": dest, "verifiable": bool(ident.get("verifiable")),
                                           "provenance": []})
            g["provenance"].append(prov)
            identity_bearing += 1
        else:
            unverifiable.append({"identity_key": "UNVERIFIABLE#%d" % len(unverifiable),
                                 "function": fn, "line": ln, "dest": dest,
                                 "verifiable": False, "provenance": [prov]})
    unique_ops = len(id_groups)
    # ASSERT the identity/denominator chain (identity-bearing records collapse to <= unique ops;
    # unverifiable records are raw but not identity-bearing).
    assert len(raw) >= identity_bearing >= unique_ops, (len(raw), identity_bearing, unique_ops)
    return {"raw_recognized_records": len(raw),
            "identity_bearing_records": identity_bearing,
            "unique_physical_operations": unique_ops,
            "identity_unverifiable_records": len(unverifiable),
            "ops": list(id_groups.values()), "unverifiable_ops": unverifiable}


def map_labeled_write(body_lines, cpp, write_line, write_dest):
    """Stage 3: locate the labeled write line in the built source and confirm it is present in
    the CPG. Returns (mapped:bool, line_no or None, detail)."""
    nl = _norm(write_line)
    cand = [i + 1 for i, ln in enumerate(body_lines) if nl and _norm(ln) == nl]
    if not cand:
        cand = [i + 1 for i, ln in enumerate(body_lines) if nl and nl in _norm(ln)]
    if not cand:
        return False, None, "labeled_line_not_in_built_source"
    d = json.load(open(cpp))
    lines_with_nodes = set()
    for c in d.get("calls", []):
        lines_with_nodes.add(c.get("line"))
    for coll in ("identifiers", "locals"):
        for n in d.get(coll, []):
            lines_with_nodes.add(n.get("line"))
    for L in cand:
        if L in lines_with_nodes:
            return True, L, "mapped"
    return False, cand[0], "labeled_line_absent_from_cpg"


def recognition_at(recs, function_names, L, write_dest):
    """Stage 4: did any producer/capability recognize a write at labeled line L with a matching
    dest? Returns (recognized, matched_records, line_only_records)."""
    rd = WSD._root_ident(write_dest or "")
    matched, line_only = [], []
    for r in recs:
        if r.get("error") or r.get("line") != L:
            continue
        line_only.append(r)
        if WSD._root_ident(r.get("dest") or "") == rd and rd:
            matched.append(r)
    return (bool(matched), matched, line_only)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/heldout_out"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10**9
    os.makedirs(outdir, exist_ok=True)
    raw_path = os.path.join(outdir, "raw_sites.jsonl")

    pool = json.load(open(os.path.join(STUDY, "pooled", "FROZEN_heldout_pooled.json")))
    sv = [s for s in pool["sites"] if s["pool_source"] == "secvuleval_full"]
    other = [s for s in pool["sites"] if s["pool_source"] != "secvuleval_full"]
    bodies = {}
    for ln in gzip.open(GZ, "rt"):
        o = json.loads(ln)
        h = hashlib.sha256(o["func_body"].encode()).hexdigest()
        if h not in bodies:
            bodies[h] = o["func_body"]

    raw = open(raw_path, "w")
    # 83 non-SecVulEval pooled sites: filepath/function source was NOT retained in the frozen
    # local manifests, so they are not reconstructable HERE. This is pipeline / data-packaging
    # attrition -- their repos+commits may still be retrievable later; it is NOT proof the
    # source no longer exists. Recorded, kept SEPARATE from scanner misses.
    for s in other:
        raw.write(json.dumps({
            "pool_source": s["pool_source"], "family_id": s["family_id"],
            "write_kind": s.get("write_kind"), "write_dest": s.get("write_dest"),
            "repository": s.get("repository") or s.get("project"),
            "commit": s.get("commit_id") or s.get("fix_commit"),
            "stage1_source_available": False,
            "pipeline_attrition": "source_not_reconstructable_from_frozen_manifest",
            "detail": "filepath/function source not retained in the frozen local manifest; "
                      "repository+commit may be retrievable later (not proof source is gone)"})
            + "\n")

    done = 0
    for s in sv:
        if done >= limit:
            break
        done += 1
        h = s["func_body_sha256"]
        row = {"pool_source": "secvuleval_full", "site_id": s["site_id"],
               "func_name": s["func_name"], "family_id": s["family_id"],
               "write_kind": s.get("write_kind"), "write_dest": s.get("write_dest"),
               "write_line": s.get("write_line"),
               # NOT a full-repository build: this is recognition from a frozen FUNCTION-LEVEL
               # source packet (missing headers/decls/macros/callers/build config may lose
               # evidence). Reported as function-packet recognition, not full-repo recall.
               "analysis_mode": "frozen_function_level_source_packet"}
        body = bodies.get(h)
        # STAGE 1: source available + sha-verified
        if body is None or hashlib.sha256(body.encode()).hexdigest() != h:
            row.update(stage1_source_available=False,
                       pipeline_attrition="body_missing_or_sha_mismatch")
            raw.write(json.dumps(row) + "\n"); continue
        row["stage1_source_available"] = True
        work = tempfile.mkdtemp()
        open(os.path.join(work, "body.c"), "w").write(body)
        out = os.path.join(work, "out")
        cpp, log = scan(work, out)
        # STAGE 2: build/parse ok
        if cpp is None:
            row.update(stage2_build_parse_ok=False, pipeline_attrition="build_or_parse_failed",
                       detail=_norm(log)[-200:])
            raw.write(json.dumps(row) + "\n"); continue
        row["stage2_build_parse_ok"] = True
        body_lines = body.splitlines()
        mapped, L, mdetail = map_labeled_write(body_lines, cpp, s.get("write_line"),
                                               s.get("write_dest"))
        row.update(stage3_labeled_write_mapped=mapped, mapped_line=L, map_detail=mdetail)
        recs = recognized_records(cpp)
        recon = reconcile_identity(cpp, recs)
        row["identity_reconciliation"] = {
            k: recon[k] for k in ("raw_recognized_records", "identity_bearing_records",
                                  "unique_physical_operations", "identity_unverifiable_records")}
        row["distinct_recognized_ops"] = (recon["unique_physical_operations"]
                                          + recon["identity_unverifiable_records"])
        row["recognized_ops"] = recon["ops"]
        row["recognized_unverifiable_ops"] = recon["unverifiable_ops"]
        if not mapped:
            row["pipeline_attrition"] = "labeled_write_not_mapped"
            raw.write(json.dumps(row) + "\n"); continue
        recog, matched, line_only = recognition_at(recs, {s["func_name"]}, L, s.get("write_dest"))
        row["stage4_recognized"] = recog
        row["matched_records"] = matched
        row["line_only_records"] = [r for r in line_only if r not in matched]
        if recog:
            # STAGE 5/6 from the best-resolved matched record
            statuses = [m.get("status") for m in matched]
            reasons = [m.get("reason") for m in matched]
            ev = any(rs not in EVIDENCE_ABSENT for rs in reasons) or \
                any(st in RESOLVED for st in statuses)
            row["stage5_evidence_established"] = bool(ev)
            if any(st in RESOLVED for st in statuses):
                rel = "resolved"
            elif ev and any(st in OPEN for st in statuses):
                rel = "open"
            else:
                rel = "missing"
            row["stage6_relationship"] = rel
        else:
            row["stage5_evidence_established"] = False
            row["stage6_relationship"] = None
        raw.write(json.dumps(row) + "\n")
        raw.flush()
    raw.close()
    print("RAW_WRITTEN", raw_path, "secvuleval_processed", done, "other_recorded", len(other))


if __name__ == "__main__":
    main()
