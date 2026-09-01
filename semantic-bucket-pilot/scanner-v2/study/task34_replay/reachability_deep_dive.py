#!/usr/bin/env python3
"""TASK34-REACH-DEEPDIVE-R01: goes beyond reachability_tier.py's own 4-tier classification
(which its own docstring explicitly scopes to registration + a real, non-transitive call check)
to answer the question raised directly: of the 3,902 staged raw candidates that never cleared
the JS-reachability gate, how many are DIRECTLY_REGISTERED (impossible -- this replay's own
funnel already confirmed 0 TIER_JS_CALL_PROVEN/TIER_REGISTERED_NOT_JS_CALLED among them), how
many are TRANSITIVELY_CALLED_FROM_REGISTERED (a registered export calls them, even indirectly),
how many look like a CALLBACK_OR_WORKER (passed as a function reference to some other call),
how many are only reachable via MODULE_LOAD_EXECUTION (transitively called from the addon's own
`Init` entry point, never from a per-method registration), and how many are GENUINELY_INTERNAL
(none of the above -- no real, resolved call-graph path from any registered export or Init).

Uses ONLY preserved bundle evidence (cpp_facts.json's own real, already-resolved
`candidate_target_ids` call edges + `arguments[].kind == METHOD_REF` function-reference
arguments) -- no new Joern run, no source re-download, no new c2cpg/jssrc2cpg invocation.
reachability_tier.py's own `build_registration_table()`/`link_napi_facts.extract_napi_bindings()`
are reused verbatim (the SAME current, live FIX01I linker task #34's own replay already used --
see this module's own confirmation note below) so this deep-dive never re-implements or drifts
from the registration logic that produced the original tier classification.

CONFIRMATION (answering the request directly): task #34's replay did NOT reuse any bundle's own
stale, capture-time `cross_language_bindings.json`. `replay_100_bundles.py` never loads that
file into a record at all -- `reachability_tier.classify_record_reachability(record, js, cpp)`
computes registration/linkage FRESH, every time, from `js_facts.json`/`cpp_facts.json` via
`reachability_tier.py`'s own live import of `link_napi_facts.extract_napi_bindings` (the current,
develop-checked-out FIX01I linker) -- the same import this deep-dive reuses. There was no stale
overnight link output to recompute away from.
"""
import json
import os
import sys
import tarfile
from collections import defaultdict, deque, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
BUNDLE_DIR = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100", "evidence_bundles_100")
sys.path.insert(0, SCANNER_V2)
import reachability_tier as rt  # noqa: E402

STAGED_KEYS = ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
               "oob_index_write_candidates", "oob_read_candidates")

CALLBACK_TAKING_APIS_SEEN = Counter()  # real, observed outer-call names a callback-shaped
                                        # argument was passed to -- reported, not assumed ahead
                                        # of time.


def load_replayed():
    out = []
    with open(os.path.join(RESULTS_DIR, "replay_records.jsonl")) as f:
        for line in f:
            line = line.strip()
            if line:
                d = json.loads(line)
                if d.get("outcome") == "REPLAYED":
                    out.append(d)
    return out


def bundle_filename(pkg_name, version):
    return f"{pkg_name.replace('/', '__')}@{version}.tar.gz"


def build_call_graph(cpp):
    """caller_function_id -> set(real, resolved callee_function_ids), from cpp['calls']'s own
    already-resolved candidate_target_ids -- never a guess, only calls Joern's own frontend
    already resolved."""
    graph = defaultdict(set)
    for c in cpp.get("calls", []):
        caller = c.get("enclosing_function_id")
        for callee in c.get("candidate_target_ids") or []:
            graph[caller].add(callee)
    return graph


def bfs_reachable(graph, roots):
    seen = set(roots)
    q = deque(roots)
    while q:
        cur = q.popleft()
        for nxt in graph.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return seen


def resolve_method_ref_targets(cpp):
    """Best-effort resolution of METHOD_REF-kind call arguments (a function referenced BY NAME,
    passed as a value, e.g. to a worker/callback-registration API) to a real function id in this
    same package -- matched by bare name, preferring a same-file candidate to disambiguate a
    common short name, exactly the same discipline extract_instancemethod_bindings() already
    uses for InstanceMethod<&Class::Method>. Zero or multiple candidates -> left unresolved,
    never guessed. Returns {referenced_function_id: [(caller_call_id, outer_call_name), ...]}."""
    fns_by_name = defaultdict(list)
    for f in cpp.get("functions", []):
        fns_by_name[f["name"]].append(f)

    refs = defaultdict(list)
    for c in cpp.get("calls", []):
        for a in c.get("arguments") or []:
            if a.get("kind") != "METHOD_REF":
                continue
            bare = (a.get("code") or a.get("name") or "").strip()
            if not bare:
                continue
            candidates = fns_by_name.get(bare, [])
            if len(candidates) == 1:
                target = candidates[0]
            elif len(candidates) > 1:
                same_file = [f for f in candidates if f.get("file") == c.get("file")]
                target = same_file[0] if len(same_file) == 1 else None
            else:
                target = None
            if target is not None:
                refs[target["id"]].append((c.get("id"), c.get("name")))
                CALLBACK_TAKING_APIS_SEEN[c.get("name")] += 1
    return refs


def classify_package(pkg_name, version, staged_candidate_fids, cpp, js):
    table = rt.build_registration_table(cpp)
    registered_ids = {fid for fid, _full in table.values()}
    init_fn_ids = {f["id"] for f in cpp.get("functions", []) if f.get("name") == "Init"}

    graph = build_call_graph(cpp)
    reachable_from_registered = bfs_reachable(graph, registered_ids) - registered_ids
    reachable_from_init = bfs_reachable(graph, init_fn_ids) - init_fn_ids
    method_ref_targets = resolve_method_ref_targets(cpp)

    out = {}
    for fid in staged_candidate_fids:
        if fid in registered_ids:
            out[fid] = "DIRECTLY_REGISTERED"
        elif fid in reachable_from_registered:
            out[fid] = "TRANSITIVELY_CALLED_FROM_REGISTERED"
        elif fid in method_ref_targets:
            out[fid] = "CALLBACK_OR_WORKER_HEURISTIC"
        elif fid in reachable_from_init:
            out[fid] = "MODULE_LOAD_EXECUTION_HEURISTIC"
        else:
            out[fid] = "GENUINELY_INTERNAL"
    return out


def main():
    replayed = load_replayed()

    # index every staged raw candidate's own function_id per package, keyed to its property +
    # its own reachability_status (already computed by the real replay) so this deep-dive's
    # own new classification can be reported ALONGSIDE the original tier, never replacing it.
    per_package_candidates = defaultdict(list)  # (pkg,ver) -> [(key, function_id, tier, f)]
    for rec in replayed:
        key_tuple = (rec["package_name"], rec["version"])
        for key in STAGED_KEYS:
            for f in rec.get(key) or []:
                per_package_candidates[key_tuple].append(
                    (key, f.get("function_id"), f.get("reachability_status"), f))

    registration_stats = []  # per-package n_registrations, for "packages with confirmed
                              # native registrations" (request item 2)
    deep = Counter()
    deep_by_property = defaultdict(Counter)
    deep_detail_examples = defaultdict(list)
    unresolved_sample_pool = []  # for the manual stratified sample of the 136

    for (pkg_name, version), items in per_package_candidates.items():
        bpath = os.path.join(BUNDLE_DIR, bundle_filename(pkg_name, version))
        with tarfile.open(bpath, "r:gz") as tf:
            cpp = json.load(tf.extractfile("cpp_facts.json"))
            js = json.load(tf.extractfile("js_facts.json"))

        table = rt.build_registration_table(cpp)
        registered_ids = {fid for fid, _full in table.values()}
        registration_stats.append({
            "package_name": pkg_name, "version": version,
            "n_registrations": len(table),
            "n_registered_function_ids": len(registered_ids),
        })

        fids = sorted(set(fid for _k, fid, _t, _f in items if fid is not None))
        classified = classify_package(pkg_name, version, fids, cpp, js)

        for key, fid, tier, f in items:
            new_bucket = classified.get(fid, "NO_FUNCTION_ID")
            deep[new_bucket] += 1
            deep_by_property[key][new_bucket] += 1
            if tier == "REACHABILITY_UNRESOLVED":
                unresolved_sample_pool.append({
                    "package_name": pkg_name, "version": version, "property": key,
                    "function": f.get("function") or f.get("function_name"),
                    "file": f.get("file"), "function_id": fid,
                    "deep_dive_bucket": new_bucket,
                })
            if len(deep_detail_examples[new_bucket]) < 5:
                deep_detail_examples[new_bucket].append({
                    "package_name": pkg_name, "version": version, "property": key,
                    "function": f.get("function") or f.get("function_name"),
                    "file": f.get("file"),
                })

    n_pkgs_with_registrations = sum(1 for r in registration_stats if r["n_registrations"] > 0)
    n_pkgs_zero_registrations = len(registration_stats) - n_pkgs_with_registrations

    # stratified manual sample of the 136 REACHABILITY_UNRESOLVED cases: one per distinct
    # package where possible, up to 20 total, for real inline inspection in the report.
    import random
    random.seed(34)  # reproducible sample selection, not hidden
    by_pkg = defaultdict(list)
    for item in unresolved_sample_pool:
        by_pkg[item["package_name"]].append(item)
    stratified_sample = []
    for pkg, items in sorted(by_pkg.items()):
        stratified_sample.append(items[0])
    if len(stratified_sample) > 20:
        stratified_sample = random.sample(stratified_sample, 20)

    out = {
        "n_packages": len(registration_stats),
        "n_packages_with_confirmed_registrations": n_pkgs_with_registrations,
        "n_packages_zero_registrations": n_pkgs_zero_registrations,
        "registration_stats_per_package": sorted(
            registration_stats, key=lambda r: -r["n_registrations"])[:20],
        "deep_dive_totals": dict(deep),
        "deep_dive_by_property": {k: dict(v) for k, v in deep_by_property.items()},
        "deep_dive_examples": {k: v for k, v in deep_detail_examples.items()},
        "callback_taking_outer_call_names_observed": dict(CALLBACK_TAKING_APIS_SEEN),
        "reachability_unresolved_total": len(unresolved_sample_pool),
        "reachability_unresolved_stratified_sample": stratified_sample,
    }
    with open(os.path.join(RESULTS_DIR, "reachability_deep_dive.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)

    print(f"n_packages={out['n_packages']} with_registrations={n_pkgs_with_registrations} "
          f"zero_registrations={n_pkgs_zero_registrations}")
    print("deep_dive_totals:", dict(deep))
    print("Wrote results/reachability_deep_dive.json")


if __name__ == "__main__":
    main()
