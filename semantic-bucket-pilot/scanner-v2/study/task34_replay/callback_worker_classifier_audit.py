#!/usr/bin/env python3
"""ROADMAP-STEP6-R01: real audit of reachability_deep_dive.py's own CALLBACK_OR_WORKER_HEURISTIC
bucket -- for the ACTUAL 124 staged candidates it matched (not the corpus-wide Counter over
every METHOD_REF anywhere, which mixes in non-candidate matches too), records the real outer
call name each one matched against. Answers directly: how many of the 124 are genuine
callback/worker-registration API calls (uv_queue_work, pthread_create, napi_create_async_work,
etc.) vs. structural noise from `resolve_method_ref_targets()`'s own overly broad METHOD_REF
match (any call with a function-reference argument, including `<operator>.assignment`,
`<operator>.arrayInitializer`, `<operator>.addressOf`, `<operator>.cast` -- none of which are
callback/worker registrations; a function pointer merely appears as an operand).

No Joern rebuild -- pure recomputation over the same preserved bundle facts
reachability_deep_dive.py already used.
"""
import json
import os
import sys
import tarfile
from collections import Counter, defaultdict

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


def main():
    replayed = dd.load_replayed()
    per_package_candidates = defaultdict(list)
    for rec in replayed:
        key_tuple = (rec["package_name"], rec["version"])
        for key in STAGED_KEYS:
            for f in rec.get(key) or []:
                per_package_candidates[key_tuple].append(
                    (key, f.get(ID_FIELD_BY_KEY[key]), f))

    outer_call_name_by_candidate = Counter()
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

        for key, fid, f in cands:
            if fid is None or fid in registered_ids or fid in reachable_from_registered:
                continue
            if fid not in method_ref_targets:
                continue
            outer_names = sorted({name for (_cid, name) in method_ref_targets[fid]})
            for name in outer_names:
                outer_call_name_by_candidate[name] += 1
            detail.append({
                "package_name": pkg_name, "version": version, "property": key,
                "function_id": fid, "outer_call_names": outer_names,
            })

    print(f"total CALLBACK_OR_WORKER_HEURISTIC candidates: {len(detail)}")
    print("outer call names, by real candidate count (not raw corpus-wide count):")
    for name, count in outer_call_name_by_candidate.most_common():
        print(f"  {count:4d}  {name}")

    out_path = os.path.join(RESULTS_DIR, "callback_worker_classifier_audit.json")
    with open(out_path, "w") as f:
        json.dump({
            "total_candidates": len(detail),
            "outer_call_name_counts": dict(outer_call_name_by_candidate),
            "detail": detail,
        }, f, indent=2, sort_keys=True)
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
