#!/usr/bin/env python3
"""ROADMAP-STEP6-R01: real audit of reachability_deep_dive.py's own MODULE_LOAD_EXECUTION_
HEURISTIC bucket -- for the ACTUAL 7 staged candidates it matched, records the real, full
clean-vs-ambiguous call-graph path from the addon's own Init function to each candidate's own
function id (single-target-resolved at every hop, or not) -- so the resulting tier is validated
with the SAME "clean edge" rigor TIER_TRANSITIVELY_CALLED_FROM_REGISTERED already received, not
merely trusted from the original heuristic's own looser (any candidate_target_ids edge, however
ambiguous) BFS.

No Joern rebuild -- pure recomputation over the same preserved bundle facts
reachability_deep_dive.py already used.
"""
import json
import os
import sys
import tarfile
from collections import defaultdict, deque

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
BUNDLE_DIR = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100", "evidence_bundles_100")
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, HERE)
import reachability_tier as rt  # noqa: E402
import reachability_deep_dive as dd  # noqa: E402

STAGED_KEYS = dd.STAGED_KEYS
ID_FIELD_BY_KEY = dd.ID_FIELD_BY_KEY


def find_clean_path_from_any(clean_edges, roots, function_id):
    parent = {}
    seen = set(roots)
    q = deque(roots)
    while q:
        cur = q.popleft()
        for callee, call_id, call_name in clean_edges.get(cur, ()):
            if callee in seen:
                continue
            seen.add(callee)
            parent[callee] = (cur, call_id, call_name)
            if callee == function_id:
                path = []
                node = callee
                while node in parent:
                    p, cid, cname = parent[node]
                    path.append({"caller_id": p, "callee_id": node, "call_id": cid,
                                 "call_site_name": cname})
                    node = p
                path.reverse()
                return path
        q.extend(callee for callee, _cid, _cname in clean_edges.get(cur, ())
                 if callee in seen and callee not in q)
    return None


def main():
    replayed = dd.load_replayed()
    per_package_candidates = defaultdict(list)
    for rec in replayed:
        key_tuple = (rec["package_name"], rec["version"])
        for key in STAGED_KEYS:
            for f in rec.get(key) or []:
                per_package_candidates[key_tuple].append((key, f.get(ID_FIELD_BY_KEY[key]), f))

    detail = []
    for (pkg_name, version), cands in per_package_candidates.items():
        bpath = os.path.join(BUNDLE_DIR, dd.bundle_filename(pkg_name, version))
        if not os.path.isfile(bpath):
            continue
        with tarfile.open(bpath, "r:gz") as tf:
            cpp = json.load(tf.extractfile("cpp_facts.json"))

        table = rt.build_registration_table(cpp)
        registered_ids = {fid for fid, _full in table.values()}
        graph = dd.build_call_graph(cpp)
        reachable_from_registered = dd.bfs_reachable(graph, registered_ids) - registered_ids
        method_ref_targets = dd.resolve_method_ref_targets(cpp)
        init_ids = {f["id"] for f in cpp.get("functions", []) if f.get("name") == "Init"}
        clean_edges = rt.build_clean_call_edges(cpp)
        fn_by_id = {f["id"]: f for f in cpp.get("functions", [])}

        for key, fid, f in cands:
            if fid is None or fid in registered_ids or fid in reachable_from_registered:
                continue
            if fid in method_ref_targets:
                continue  # would be CALLBACK_OR_WORKER, not this bucket
            reachable_from_init_loose = fid in dd.bfs_reachable(graph, init_ids) - init_ids
            if not reachable_from_init_loose:
                continue
            clean_path = find_clean_path_from_any(clean_edges, init_ids, fid)
            detail.append({
                "package_name": pkg_name, "version": version, "property": key,
                "function_id": fid, "function_name": fn_by_id.get(fid, {}).get("name"),
                "function_file": fn_by_id.get(fid, {}).get("file"),
                "clean_path_from_init_exists": clean_path is not None,
                "clean_path": clean_path,
            })

    n_clean = sum(1 for d in detail if d["clean_path_from_init_exists"])
    print(f"total MODULE_LOAD_EXECUTION_HEURISTIC candidates (real, per-candidate): {len(detail)}")
    print(f"of those, CLEAN (single-target-resolved at every hop) path from Init exists: {n_clean}")
    for d in detail:
        print(f"  {d['package_name']}@{d['version']} {d['property']} "
              f"{d['function_name']} ({d['function_file']}): clean={d['clean_path_from_init_exists']}")

    out_path = os.path.join(RESULTS_DIR, "module_load_classifier_audit.json")
    with open(out_path, "w") as f:
        json.dump({"total_candidates": len(detail), "n_clean": n_clean, "detail": detail},
                   f, indent=2, sort_keys=True)
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
