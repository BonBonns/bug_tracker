#!/usr/bin/env python3
"""TASK32-REOPEN step 2a: re-derives the ACTUAL call-graph path (not just BFS-set membership)
for each of the 5 real TRANSITIVELY_CALLED_FROM_REGISTERED candidates the deep-dive found, and
validates "every edge resolves by node identity" (direct instruction): a call resolves via
`candidate_target_ids`, which can carry MORE THAN ONE id when c2cpg could not disambiguate a
polymorphic/overloaded call -- an edge built from such a call is NOT a clean, single-target
resolution, even though the target id is technically present in the union. This module walks
each real path hop-by-hop and requires EVERY edge on it to come from a call whose own
candidate_target_ids has EXACTLY ONE entry -- never a guess among several.

Uses only preserved bundle evidence (cpp_facts.json's own already-resolved call edges) -- no new
Joern run.
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

# The 4 distinct (package, function_id) targets the deep-dive classified as
# TRANSITIVELY_CALLED_FROM_REGISTERED (5 findings, bindRaw shared by 2) -- identified directly
# from results/reachability_deep_dive.json + a targeted rerun of classify_package(), not assumed.
TARGETS = [
    ("@abandonware/bluetooth-hci-socket", "0.5.3-12", 107374182414, "bindRaw"),
    ("@confluentinc/kafka-javascript", "1.10.0", 107374186150, "mtx_lock"),
    ("@confluentinc/kafka-javascript", "1.10.0", 107374186183, "rwlock_rdlock"),
    ("@eliyya/sange", "1.2.0", 107374182564, "lock"),
]


def build_clean_edges(cpp):
    """caller_function_id -> [(callee_function_id, call_id, call_name)], but ONLY for calls
    whose own candidate_target_ids resolves to EXACTLY ONE real function id -- an ambiguous/
    ploymorphic call (more than one candidate) is excluded entirely, never included as a clean
    edge even though its own real target id technically sits inside the union. Returns
    (clean_edges, ambiguous_edge_count) for disclosure."""
    clean = defaultdict(list)
    ambiguous = 0
    for c in cpp.get("calls", []):
        targets = c.get("candidate_target_ids") or []
        if len(targets) == 1:
            clean[c.get("enclosing_function_id")].append(
                (targets[0], c.get("id"), c.get("name")))
        elif len(targets) > 1:
            ambiguous += 1
    return clean, ambiguous


def bfs_shortest_path(clean_edges, roots, target):
    """Real BFS over ONLY clean (single-target) edges, returning the shortest real path as a
    list of (caller_id, callee_id, call_id, call_name) hops from some root to target, or None
    if no such clean path exists."""
    parent = {}  # child_id -> (parent_id, call_id, call_name)
    seen = set(roots)
    q = deque(roots)
    if target in seen:
        return []  # target is itself a root (shouldn't happen here -- these are exactly the
                    # candidates that already failed DIRECTLY_REGISTERED)
    while q:
        cur = q.popleft()
        for callee, call_id, call_name in clean_edges.get(cur, ()):
            if callee not in seen:
                seen.add(callee)
                parent[callee] = (cur, call_id, call_name)
                if callee == target:
                    path = []
                    node = callee
                    while node in parent:
                        p, cid, cname = parent[node]
                        path.append((p, node, cid, cname))
                        node = p
                    path.reverse()
                    return path
                q.append(callee)
    return None


def main():
    results = []
    for pkg, ver, fid, fname in TARGETS:
        bpath = os.path.join(BUNDLE_DIR, dd.bundle_filename(pkg, ver))
        with tarfile.open(bpath, "r:gz") as tf:
            cpp = json.load(tf.extractfile("cpp_facts.json"))

        table = rt.build_registration_table(cpp)
        registered_ids = {rfid for rfid, _full in table.values()}
        clean_edges, n_ambiguous_total = build_clean_edges(cpp)

        path = bfs_shortest_path(clean_edges, registered_ids, fid)
        fn_by_id = {f["id"]: f for f in cpp.get("functions", [])}

        if path is None:
            results.append({
                "package": pkg, "version": ver, "function_id": fid, "function": fname,
                "clean_path_exists": False,
                "note": "No path exists using ONLY clean (single-target-resolved) edges -- the "
                        "original BFS (which unions ALL candidate_target_ids, including "
                        "ambiguous multi-target calls) found a path, but it relies on at least "
                        "one ambiguous edge. Per direct instruction (\"promote only if every "
                        "edge resolves by node identity\"), this candidate does NOT validate "
                        "and must NOT be promoted.",
            })
            continue

        hops = []
        for caller_id, callee_id, call_id, call_name in path:
            caller_fn = fn_by_id.get(caller_id, {})
            callee_fn = fn_by_id.get(callee_id, {})
            hops.append({
                "caller_id": caller_id, "caller_name": caller_fn.get("full_name"),
                "callee_id": callee_id, "callee_name": callee_fn.get("full_name"),
                "call_id": call_id, "call_site_name": call_name,
            })
        root_id = path[0][0]
        root_binding_name = next((name for name, (rfid, _f) in table.items()
                                   if rfid == root_id), None)
        results.append({
            "package": pkg, "version": ver, "function_id": fid, "function": fname,
            "clean_path_exists": True,
            "path_length_hops": len(path),
            "root_registered_function_id": root_id,
            "root_js_binding_name": root_binding_name,
            "hops": hops,
        })

    n_validated = sum(1 for r in results if r["clean_path_exists"])
    out = {"targets_checked": len(TARGETS), "validated": n_validated,
           "not_validated": len(TARGETS) - n_validated, "detail": results}
    with open(os.path.join(RESULTS_DIR, "transitive_path_validation.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)

    print(f"targets_checked={len(TARGETS)} validated={n_validated} "
          f"not_validated={len(TARGETS) - n_validated}")
    for r in results:
        print(f"  {r['package']}@{r['version']} {r['function']} (fid={r['function_id']}): "
              f"{'VALIDATED' if r['clean_path_exists'] else 'REJECTED'}"
              + (f" ({r['path_length_hops']} hops via {r['root_js_binding_name']})"
                 if r["clean_path_exists"] else ""))


if __name__ == "__main__":
    main()
