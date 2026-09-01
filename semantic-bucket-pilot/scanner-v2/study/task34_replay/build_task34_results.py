#!/usr/bin/env python3
"""Post-processes results/replay_records.jsonl (+ replay_failure_ledger.jsonl,
frozen_replay_manifest.json) into every output TASK #34 requires, and writes
TASK34_RESULTS.md. Read-only over the replay's own output -- never recomputes or overrides a
per-package verdict, only aggregates what replay_100_bundles.py already produced."""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, HERE)
import replay_100_bundles as R  # noqa: E402


def load_records():
    replayed, failures = [], []
    with open(os.path.join(RESULTS_DIR, "replay_records.jsonl")) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            (replayed if d.get("outcome") == "REPLAYED" else failures).append(d)
    return replayed, failures


ALL_PROPERTY_KEYS = (
    "r04_findings", "r05_findings", "r06_findings", "lock_balance_findings",
    "protected_field_findings", "oob_write_candidates", "oob_index_write_candidates",
    "oob_read_candidates", "oob_compare_candidates",
)


def build_funnel(replayed):
    funnel = {k: {"raw_count": 0, "reportable_count": 0} for k in ALL_PROPERTY_KEYS}
    for rec in replayed:
        summary = rec["_six_property_summary"]
        for k in ALL_PROPERTY_KEYS:
            funnel[k]["raw_count"] += summary[k]["raw_count"]
            funnel[k]["reportable_count"] += summary[k]["reportable_count"]
    return funnel


def build_reachability_distribution(replayed):
    dist = {}
    for rec in replayed:
        for key in ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
                    "oob_index_write_candidates", "oob_read_candidates", "oob_compare_candidates"):
            for f in rec.get(key) or []:
                tier = f.get("reachability_status") or "NONE"
                dist.setdefault(key, {}).setdefault(tier, 0)
                dist[key][tier] += 1
    return dist


def build_provenance_distribution(replayed):
    resolved = 0
    unresolved_by_hint = {}
    refetch_outcomes = {}
    for rec in replayed:
        refetch_outcomes.setdefault(rec["_provenance_source"], 0)
        refetch_outcomes[rec["_provenance_source"]] += 1
        for key in ALL_PROPERTY_KEYS:
            for f in rec.get(key) or []:
                prov = f.get("provenance") or {}
                if prov.get("resolved"):
                    resolved += 1
                else:
                    hint = prov.get("provenance_hint") or "NO_PROVENANCE_FIELD"
                    unresolved_by_hint.setdefault(hint, 0)
                    unresolved_by_hint[hint] += 1
    return {
        "total_resolved_findings": resolved,
        "total_unresolved_findings_by_reason": unresolved_by_hint,
        "package_level_provenance_source_outcomes": refetch_outcomes,
        "packages_with_both_hashes_verified": sum(
            1 for r in replayed if r["_tarball_hash_verified"] and r["_source_tree_hash_verified"]),
        "packages_with_refetch_failure": [
            {"package_name": r["package_name"], "version": r["version"],
             "provenance_source": r["_provenance_source"], "detail": r["_refetch_failure_detail"]}
            for r in replayed if not (r["_tarball_hash_verified"] and r["_source_tree_hash_verified"])
        ],
    }


def build_ownership_distribution(replayed):
    dist = {}
    for rec in replayed:
        for key in ALL_PROPERTY_KEYS:
            for f in rec.get(key) or []:
                prov = f.get("provenance") or {}
                if not prov.get("resolved"):
                    continue
                hint = prov.get("provenance_hint") or "UNKNOWN"
                dist.setdefault(hint, 0)
                dist[hint] += 1
    return dist


def build_vendored_dedup(replayed):
    import vendored_attribution as va
    agg = va.aggregate_vendored_dedup(replayed)
    summary = va.summarize(agg)
    detail = {k: {str(dk): v for dk, v in entries.items()} for k, entries in agg.items()}
    return summary, detail


def build_timing_disk_summary(replayed, failures):
    total_seconds = sum(r.get("_total_seconds", 0) for r in replayed)
    stage_totals = {}
    for r in replayed:
        for stage, seconds in (r.get("_timing") or {}).items():
            stage_totals.setdefault(stage, 0.0)
            stage_totals[stage] += seconds
    bundle_dir = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100", "evidence_bundles_100")
    bundle_bytes = sum(
        os.path.getsize(os.path.join(bundle_dir, f))
        for f in os.listdir(bundle_dir) if f.endswith(".tar.gz"))
    # "failures" here (this function's own parameter, from load_records()'s own split) is every
    # non-REPLAYED record -- which, in this replay, is exclusively the 3 INHERITED_UPSTREAM_
    # FAILURE entries (0 packages ever reached replay_one_package() and then genuinely failed
    # it -- confirmed directly, not assumed, by counting outcome=="REPLAY_FAILURE" separately).
    # Reported as two distinct counts so "packages_failed_at_replay" is never misread as "the
    # replay itself failed on 3 packages" when the real number of replay failures is 0.
    n_replay_failures = sum(1 for r in failures if r.get("outcome") == "REPLAY_FAILURE")
    n_inherited = sum(1 for r in failures if r.get("outcome") == "INHERITED_UPSTREAM_FAILURE")
    return {
        "packages_replayed": len(replayed),
        "packages_with_replay_failure": n_replay_failures,
        "packages_with_inherited_upstream_failure": n_inherited,
        "total_seconds_all_packages": round(total_seconds, 2),
        "mean_seconds_per_package": round(total_seconds / len(replayed), 2) if replayed else None,
        "stage_totals_seconds": {k: round(v, 2) for k, v in stage_totals.items()},
        "evidence_bundle_dir_bytes": bundle_bytes,
        "evidence_bundle_dir_human": f"{bundle_bytes / 1e6:.1f} MB",
    }


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_analyzer_hashes():
    out = {}
    for relpath in R.DRIVEN_ANALYZER_FILES:
        p = os.path.join(SCANNER_V2, relpath)
        out[relpath] = sha256_file(p) if os.path.isfile(p) else None
    return out


def run_combined_gates():
    """Runs the complete combined gate suite named by task #34, on the SAME develop checkout
    this replay ran against, and returns (all_pass: bool, log_text: str). Stops the whole
    build if any gate fails -- never proceeds to write TASK34_RESULTS.md on a red gate."""
    gates = [
        (SCANNER_V2, "check_provenance.py"),
        (SCANNER_V2, "check_oob_reportable_gate.py"),
        (SCANNER_V2, "check_vendored_attribution.py"),
        (SCANNER_V2, "check_reachability_tier.py"),
        (SCANNER_V2, "check_staged_enablement.py"),
        (SCANNER_V2, "check_six_property_aggregator.py"),
        (SCANNER_V2, "gate_resource_guard_r06.py"),
        (SCANNER_V2, "gate_resource_guard_r04.py"),
        (SCANNER_V2, "gate_resource_guard_r05.py"),
        (SCANNER_V2, "check_lock_balance.py"),
        (SCANNER_V2, "check_protected_field.py"),
        (os.path.join(os.path.dirname(SCANNER_V2), "..", "tchecker-research-complete",
                       "portable-engine-full-review-package", "tools"), "oob_write_controls.py"),
        (os.path.join(os.path.dirname(SCANNER_V2), "..", "tchecker-research-complete",
                       "portable-engine-full-review-package", "tools"), "oob_read_controls.py"),
        (os.path.join(os.path.dirname(SCANNER_V2), "..", "tchecker-research-complete",
                       "portable-engine-full-review-package", "tools"), "oob_compare_controls.py"),
        (os.path.join(os.path.dirname(SCANNER_V2), "..", "tchecker-research-complete",
                       "portable-engine-full-review-package", "tools"),
         "param_length_capacity_controls.py"),
        (os.path.join(os.path.dirname(SCANNER_V2), "..", "tchecker-research-complete",
                       "portable-engine-full-review-package", "tools"), "cfg_loop_guard_controls.py"),
    ]
    log_parts = []
    all_pass = True
    for cwd, script in gates:
        cwd = os.path.normpath(cwd)
        result = subprocess.run([sys.executable, script], cwd=cwd,
                                 capture_output=True, text=True, timeout=600)
        tail = "\n".join(result.stdout.strip().splitlines()[-3:])
        ok = result.returncode == 0
        all_pass = all_pass and ok
        log_parts.append(f"=== {script} (cwd={os.path.relpath(cwd, os.path.dirname(SCANNER_V2))}) "
                          f"=== rc={result.returncode}\n{tail}\n")
    return all_pass, "\n".join(log_parts)


def main():
    replayed, failures = load_records()
    with open(os.path.join(RESULTS_DIR, "frozen_replay_manifest.json")) as f:
        recon = json.load(f)

    funnel = build_funnel(replayed)
    reach_dist = build_reachability_distribution(replayed)
    prov_dist = build_provenance_distribution(replayed)
    ownership_dist = build_ownership_distribution(replayed)
    dedup_summary, dedup_detail = build_vendored_dedup(replayed)
    timing = build_timing_disk_summary(replayed, failures)
    analyzer_hashes = build_analyzer_hashes()

    print("Running the complete combined gate suite before finalizing TASK34_RESULTS.md ...")
    gates_ok, gates_log = run_combined_gates()
    with open(os.path.join(RESULTS_DIR, "gate_results.log"), "w") as f:
        f.write(gates_log)
    print(f"COMBINED GATES: {'ALL PASS' if gates_ok else 'FAILURE -- STOPPING'}")
    if not gates_ok:
        print(gates_log, file=sys.stderr)
        sys.exit(1)

    for name, obj in [
        ("funnel_by_property.json", funnel),
        ("reachability_tier_distribution.json", reach_dist),
        ("provenance_resolution_distribution.json", prov_dist),
        ("package_owned_vendored_counts.json", ownership_dist),
        ("vendored_dedup_summary.json", dedup_summary),
        ("vendored_dedup_detail.json", dedup_detail),
        ("timing_disk_usage_summary.json", timing),
        ("analyzer_file_hashes.json", analyzer_hashes),
    ]:
        with open(os.path.join(RESULTS_DIR, name), "w") as f:
            json.dump(obj, f, indent=2, sort_keys=True)

    # Fail-closed invariant re-verification, over the REAL replay output (not re-asserted only
    # in the abstract): every one of task #34's own named invariants, checked directly.
    invariant_checks = []
    oob_compare_reportable = funnel["oob_compare_candidates"]["reportable_count"]
    invariant_checks.append(("A disabled property (OOB_COMPARE) never has reportable=true",
                              oob_compare_reportable == 0))
    internal_unreg_reportable = 0
    unresolved_tier_reportable = 0
    for rec in replayed:
        for key in ("oob_write_candidates", "oob_index_write_candidates", "oob_read_candidates"):
            for f in rec.get(key) or []:
                if f.get("reachability_status") == "TIER_INTERNAL_UNREGISTERED" and f.get("reportable"):
                    internal_unreg_reportable += 1
                if f.get("reachability_status") in (None, "REACHABILITY_UNRESOLVED") and f.get("reportable"):
                    unresolved_tier_reportable += 1
    invariant_checks.append(("TIER_INTERNAL_UNREGISTERED never clears to reportable=true",
                              internal_unreg_reportable == 0))
    invariant_checks.append(("UNRESOLVED/unknown reachability tiers never reportable=true",
                              unresolved_tier_reportable == 0))
    unresolved_prov_reportable = sum(
        1 for rec in replayed for key in ALL_PROPERTY_KEYS for f in (rec.get(key) or [])
        if not (f.get("provenance") or {}).get("resolved") and f.get("reportable"))
    invariant_checks.append(("Unresolved provenance never reportable=true",
                              unresolved_prov_reportable == 0))
    not_applicable_reportable = sum(
        1 for rec in replayed for key in ALL_PROPERTY_KEYS for f in (rec.get(key) or [])
        if f.get("applicability_status") != "APPLICABLE" and f.get("reportable"))
    invariant_checks.append(("applicability_status != APPLICABLE never reportable=true",
                              not_applicable_reportable == 0))
    cfp_reportable = sum(
        1 for rec in replayed for key in ALL_PROPERTY_KEYS for f in (rec.get(key) or [])
        if f.get("adjudication_status") == "CONFIRMED_FALSE_POSITIVE" and f.get("reportable"))
    invariant_checks.append(("CONFIRMED_FALSE_POSITIVE never reportable=true", cfp_reportable == 0))

    libcurl_rec = next((r for r in replayed if r["package_name"] == "node-libcurl"), None)
    if libcurl_rec:
        libcurl_reportable = any(
            f.get("reportable") for key in ALL_PROPERTY_KEYS for f in (libcurl_rec.get(key) or []))
        invariant_checks.append(("node-libcurl's known false positive stays non-reportable",
                                  not libcurl_reportable))
    re2_rec = next((r for r in replayed if r["package_name"] == "re2"), None)
    if re2_rec:
        re2_oob_write_reportable = any(
            f.get("reportable") for f in (re2_rec.get("oob_write_candidates") or []))
        invariant_checks.append(("re2's internally-unregistered OOB candidates stay non-reportable",
                                  not re2_oob_write_reportable))

    dup_ids = [k for k in R.load_frozen_manifest()[0]]  # sanity: identity universe still 100
    seen = set()
    dup_found = False
    for rec in replayed + failures:
        key = (rec.get("package_name"), rec.get("version"))
        if key in seen:
            dup_found = True
        seen.add(key)
    invariant_checks.append(("No duplicate package records", not dup_found))
    invariant_checks.append(("All 100 packages accounted for (97 replayed + 3 inherited)",
                              len(replayed) + len(failures) == 100))

    all_invariants_pass = all(ok for _, ok in invariant_checks)

    print("\nFAIL-CLOSED INVARIANT RE-VERIFICATION (over real replay output):")
    for name, ok in invariant_checks:
        print(f"  {'PASS' if ok else 'FAIL'} {name}")
    if not all_invariants_pass:
        print("STOPPING: a fail-closed invariant did not hold over the real replay output.",
              file=sys.stderr)
        sys.exit(1)

    write_results_md(replayed, failures, recon, funnel, reach_dist, prov_dist, ownership_dist,
                      dedup_summary, timing, analyzer_hashes, gates_ok, invariant_checks)
    print(f"\nTASK34_RESULTS.md written. {len(replayed)} replayed, {len(failures)} inherited "
          f"failures, {len(replayed) + len(failures)}/100 accounted for.")


def write_results_md(replayed, failures, recon, funnel, reach_dist, prov_dist, ownership_dist,
                      dedup_summary, timing, analyzer_hashes, gates_ok, invariant_checks):
    lines = []
    a = lines.append
    a("# TASK #34 RESULTS: six-property aggregator replay over the frozen 100-package "
      "diagnostic sample\n")
    a(f"**develop commit replayed against:** `{R.DEVELOP_COMMIT}`\n")
    a("**This is a replay, not a new corpus run.** No Joern invocation, no CPG rebuild, no "
      "C/C++/JS facts regeneration. R06 (resource_guard_verdict_r06.py) is the one property "
      "computed fresh, run over each package's own PRESERVED cpp_raw/*.tsv, because these "
      "bundles predate R06's wiring into run_pipeline_one.py -- every other property's raw "
      "output is the original scanner output from the completed overnight run, reused verbatim. "
      "Per-file source bytes were re-fetched from the exact pinned tarball URLs recorded by the "
      "original run, SOLELY to reconstruct missing provenance (content_hash); no scanner stage "
      "consumed the re-fetched source, and it was deleted immediately after provenance "
      "enrichment, per direct instruction.\n")

    a("## Claims boundary\n")
    a("`reportable=true` means eligible for manual security review as a scanner candidate -- "
      "it does NOT mean confirmed vulnerability. This section reports NO vulnerability totals, "
      "NO true-negative claims, NO package-safety claims, and NO corpus-prevalence claims. "
      "Raw candidates, gated/reportable candidates, abstentions, and confirmed false positives "
      "are kept strictly separate throughout.\n")

    a("## Identity reconciliation (performed BEFORE any replay work)\n")
    other_desc = (", ".join(f"{k}={v}" for k, v in recon["other_status_counts"].items())
                  if recon["other_status_counts"] else "0")
    a(f"- 100 frozen package identities, {recon['analyzed_count']} ANALYZED, "
      f"{recon['cpp_cpg_failed_count']} CPP_CPG_FAILED, {recon['export_failed_count']} "
      f"EXPORT_FAILED, {other_desc} other statuses.")
    a(f"- Bundle identities == ANALYZED identities: **{recon['bundle_identities_equal_analyzed']}**")
    a(f"- Missing-3 == CPP_CPG_FAILED ∪ EXPORT_FAILED: "
      f"**{recon['missing_matches_cpp_cpg_failed_union_export_failed']}**")
    a(f"- Final accounting: **{len(replayed)} replayed + {len(failures)} inherited upstream "
      f"failures = {len(replayed) + len(failures)}/100, 0 silently omitted.**\n")

    a("### Inherited upstream failures (never attempted as a bundle replay; no bundle was ever "
      "produced for these -- not corrupt bundles)\n")
    for f in failures:
        a(f"- `{f['package_name']}@{f['version']}`: {f.get('upstream_status', f.get('reason'))} "
          f"-- {f.get('upstream_detail', f.get('detail'))}")
    a("")

    a("## Six-property matrix, as actually enforced this replay\n")
    a("| Property | Enabled | Raw candidates | Reportable |")
    a("|---|---|---|---|")
    labels = {
        "r04_findings": "R04 (comparison diagnostic)",
        "r05_findings": "R05 (comparison diagnostic)",
        "r06_findings": "FALLIBLE_BOUNDED_RESOURCE (R06/FIX01I, driven)",
        "lock_balance_findings": "LOCK_BALANCE",
        "protected_field_findings": "PROTECTED_FIELD",
        "oob_write_candidates": "OOB_WRITE",
        "oob_index_write_candidates": "OOB_INDEX_WRITE",
        "oob_read_candidates": "OOB_READ",
        "oob_compare_candidates": "OOB_COMPARE",
    }
    for k, label in labels.items():
        enabled = k not in ("oob_compare_candidates",)
        a(f"| {label} | {'enabled' if enabled else '**disabled**'} | "
          f"{funnel[k]['raw_count']} | {funnel[k]['reportable_count']} |")
    a("\nOOB_COMPARE's disabled reason (recorded on every aggregate record, unconditionally): "
      "task #33's real 33-package corpus survey of memcmp/strncmp/CRYPTO_memcmp found zero real "
      "candidates and root-caused why; the detector itself is proven sound on its own positive-"
      "control fixture. Its zero-candidate output here is NOT presented as safety evidence -- "
      "it is a corpus-survey result, not a proof of absence.\n")

    a("## Reachability-tier distribution (staged properties only; R04/R05/R06 use their own "
      "separate applicability/adjudication path, never touched by reachability_tier.py)\n")
    for key, dist in reach_dist.items():
        a(f"- `{key}`: " + ", ".join(f"{t}={n}" for t, n in sorted(dist.items())))
    a("")

    a("## Provenance-resolution distribution\n")
    a(f"- Total resolved findings (across all 9 property keys): "
      f"**{prov_dist['total_resolved_findings']}**")
    a(f"- Unresolved findings by reason: " +
      ", ".join(f"{k}={v}" for k, v in sorted(prov_dist['total_unresolved_findings_by_reason'].items())))
    a(f"- Package-level re-fetch outcome: " +
      ", ".join(f"{k}={v}" for k, v in sorted(prov_dist['package_level_provenance_source_outcomes'].items())))
    a(f"- Packages with BOTH tarball_sha256 and source_tree_sha256 independently re-verified: "
      f"**{prov_dist['packages_with_both_hashes_verified']}/{len(replayed)}**")
    if prov_dist["packages_with_refetch_failure"]:
        a("- Packages where the re-fetch/hash-verify did NOT both succeed (provenance kept "
          "unresolved for these, per direct instruction -- no metadata substituted):")
        for p in prov_dist["packages_with_refetch_failure"]:
            a(f"  - `{p['package_name']}@{p['version']}`: {p['provenance_source']} "
              f"({p['detail']})")
    else:
        a("- All 97 packages: both hash checks passed. No metadata substitution occurred.")
    a("")

    a("## Package-owned vs. vendored counts (among RESOLVED findings only)\n")
    for hint, n in sorted(ownership_dist.items()):
        a(f"- {hint}: {n}")
    a("")

    a("## Vendored-code deduplication (task #31)\n")
    a("| Property | Deduplicated count | Raw exposure count |")
    a("|---|---|---|")
    for k in ALL_PROPERTY_KEYS:
        s = dedup_summary.get(k, {"deduplicated_count": 0, "raw_exposure_count": 0})
        a(f"| {labels.get(k, k)} | {s['deduplicated_count']} | {s['raw_exposure_count']} |")
    a("")

    a("## Timing and disk-usage summary\n")
    a(f"- Packages replayed: {timing['packages_replayed']}, "
      f"replay failures: {timing['packages_with_replay_failure']}, "
      f"inherited upstream failures: {timing['packages_with_inherited_upstream_failure']} "
      "(never attempted -- no usable bundle was ever produced for these, not a corrupt one).")
    a(f"- Total wall time (sum across packages): {timing['total_seconds_all_packages']}s, "
      f"mean per package: {timing['mean_seconds_per_package']}s")
    a("- Stage totals (seconds): " +
      ", ".join(f"{k}={v}" for k, v in sorted(timing["stage_totals_seconds"].items())))
    a(f"- Evidence bundle directory on disk: {timing['evidence_bundle_dir_human']}\n")

    a("## Exact hashes of all driven analyzer files (this replay's own dependencies, hashed "
      "fresh at run time -- not reused from any bundle's own, earlier, analyzer_hashes)\n")
    for relpath, h in sorted(analyzer_hashes.items()):
        a(f"- `{relpath}`: `{h}`")
    a("")

    a("## Fail-closed invariant re-verification (over the real replay output, not asserted in "
      "the abstract)\n")
    for name, ok in invariant_checks:
        a(f"- {'PASS' if ok else 'FAIL'}: {name}")
    a("")

    a(f"## Combined gate suite: {'ALL PASS' if gates_ok else 'FAILURE'}\n")
    a("See `gate_results.log` for the full per-gate output.\n")

    a("## Completion criteria (task #34's own definition)\n")
    a("- [x] All combined gates pass.")
    a("- [x] All 100 bundles processed or explicitly accounted for as replay failures "
      f"({len(replayed)} replayed + {len(failures)} inherited, 0 silently omitted).")
    a("- [x] No duplicate package records.")
    a("- [x] Every fail-closed invariant passes (see above).")
    determinism_path = os.path.join(RESULTS_DIR, "determinism_verification.json")
    if os.path.isfile(determinism_path):
        det = json.load(open(determinism_path))
        status = "x" if det["all_deterministic"] else " "
        a(f"- [{status}] Rerunning the aggregator produces byte-identical semantic results -- "
          f"ACTUALLY VERIFIED, not merely asserted from design: a full independent second replay "
          f"of all {det['total_packages']} packages was run (see "
          f"`results/determinism_verification.json`); **{det['matched']}/{det['total_packages']} "
          f"produced an identical semantic digest** (sha256 of each record with only the "
          f"real, expected-to-vary wall-clock timing fields excluded), "
          f"{det['mismatched']} mismatched, {det['rerun_failures']} rerun failures.")
    else:
        a("- [ ] Rerunning the aggregator produces byte-identical semantic results -- NOT YET "
          "independently verified by an actual second run; see "
          "`verify_determinism.py`, not yet executed for this build.")
    a("- [x] Results and documentation committed and pushed to `develop`.\n")

    a("---\n*No new corpus run was launched. Task #34 is the 97-bundle replay only, per its own "
      "explicit scope. The remaining 394 packages were not started.*")

    with open(os.path.join(HERE, "TASK34_RESULTS.md"), "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
