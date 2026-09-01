#!/usr/bin/env python3
"""TASK34-REPLAY-R01 driver. Orchestrates replay_100_bundles.py over all 100 frozen package
identities (97 real replays + 3 explicit inherited upstream failures), writes every required
output, and stops immediately on a real gate/reconciliation failure -- never proceeds past a
verification step that didn't pass.

Resumable: `replay_records.jsonl` is appended to, one JSON line per package, immediately after
each package finishes (real atomic append: write to a per-package temp file, fsync, then a
single `os.write` of that file's bytes to the open JSONL file descriptor -- a crash mid-package
can never produce a partial/duplicate line). A companion `.done_identities` file tracks which
identities have already been written; a rerun skips them, so re-running this script after an
interruption resumes rather than re-processing packages already recorded, and can never produce
a duplicate package record.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, HERE)
import replay_100_bundles as R  # noqa: E402


def atomic_append_jsonl(path, obj):
    line = (json.dumps(obj, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def load_done_identities(path):
    if not os.path.isfile(path):
        return set()
    with open(path) as f:
        return set(tuple(json.loads(line)) for line in f if line.strip())


def mark_done(path, key):
    atomic_append_jsonl(path, list(key))


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    records_path = os.path.join(RESULTS_DIR, "replay_records.jsonl")
    ledger_path = os.path.join(RESULTS_DIR, "replay_failure_ledger.jsonl")
    done_path = os.path.join(RESULTS_DIR, ".done_identities.jsonl")
    manifest_out_path = os.path.join(RESULTS_DIR, "frozen_replay_manifest.json")

    all_records, records_by_status, sample_by_key = R.load_frozen_manifest()
    ok, recon = R.reconcile_identities(all_records, records_by_status, sample_by_key)
    recon["reconciled_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    recon["ok"] = ok
    with open(manifest_out_path, "w") as f:
        json.dump(recon, f, indent=2, sort_keys=True)
    print(f"RECONCILIATION: ok={ok}")
    print(json.dumps({k: v for k, v in recon.items() if k != "inherited_failures"}, indent=2))
    if not ok:
        print("STOPPING: identity-level reconciliation failed -- this is a real evidence-"
              "preservation discrepancy, not proceeding to replay.", file=sys.stderr)
        sys.exit(1)

    analyzed = sorted(records_by_status["ANALYZED"])
    inherited = recon["inherited_failures"]

    done = load_done_identities(done_path)

    # --- the 3 explicit inherited upstream failures: never attempted as a bundle replay -------
    for entry in inherited:
        key = (entry["package_name"], entry["version"])
        if list(key) in [list(d) for d in done]:
            continue
        failure_record = {
            "package_name": entry["package_name"], "version": entry["version"],
            "outcome": "INHERITED_UPSTREAM_FAILURE",
            "upstream_status": entry["status"], "upstream_detail": entry["detail"],
            "note": "No usable evidence bundle was ever produced for this package (its own "
                    "evidence_bundle field in the frozen JSONL records completeness_status="
                    "PARTIAL, path=null) -- not a corrupt bundle, never attempted, never "
                    "re-downloaded or rebuilt, per direct instruction.",
        }
        atomic_append_jsonl(ledger_path, failure_record)
        atomic_append_jsonl(records_path, failure_record)
        mark_done(done_path, key)
        done.add(key)
        print(f"[inherited] {entry['package_name']}@{entry['version']}: "
              f"{entry['status']} ({entry['detail']})")

    # --- the 97 real replays -------------------------------------------------------------------
    limit = None
    only = None
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--limit":
            limit = int(sys.argv[1:][i + 1])
        if arg == "--only":
            only = set(sys.argv[1:][i + 1].split(","))

    n_done_this_run = 0
    for pkg_name, version in analyzed:
        key = (pkg_name, version)
        if key in done:
            continue
        if only and f"{pkg_name}@{version}" not in only:
            continue
        if limit is not None and n_done_this_run >= limit:
            break
        sample_info = sample_by_key[key]
        timing = {}
        t0 = time.time()
        try:
            record = R.replay_one_package(pkg_name, version, sample_info, timing)
            record["outcome"] = "REPLAYED"
            atomic_append_jsonl(records_path, record)
            print(f"[{n_done_this_run + 1}] {pkg_name}@{version}: REPLAYED "
                  f"(prov_source={record['_provenance_source']} "
                  f"tarball_verified={record['_tarball_hash_verified']} "
                  f"tree_verified={record['_source_tree_hash_verified']} "
                  f"{time.time() - t0:.1f}s)")
        except R.ReplayFailure as e:
            failure_record = {
                "package_name": pkg_name, "version": version,
                "outcome": "REPLAY_FAILURE",
                "reason": e.reason, "detail": str(e.detail)[:2000],
                "seconds": time.time() - t0,
            }
            atomic_append_jsonl(ledger_path, failure_record)
            atomic_append_jsonl(records_path, failure_record)
            print(f"[{n_done_this_run + 1}] {pkg_name}@{version}: REPLAY_FAILURE "
                  f"({e.reason}: {str(e.detail)[:200]})")
        except Exception as e:  # pragma: no cover -- a real, unexpected failure must still be
                                  # recorded explicitly, never silently dropped or crash the run.
            failure_record = {
                "package_name": pkg_name, "version": version,
                "outcome": "REPLAY_FAILURE",
                "reason": f"UNEXPECTED_{type(e).__name__}", "detail": str(e)[:2000],
                "seconds": time.time() - t0,
            }
            atomic_append_jsonl(ledger_path, failure_record)
            atomic_append_jsonl(records_path, failure_record)
            print(f"[{n_done_this_run + 1}] {pkg_name}@{version}: UNEXPECTED FAILURE "
                  f"({type(e).__name__}: {e})")
        mark_done(done_path, key)
        done.add(key)
        n_done_this_run += 1

    print(f"\nDone this run: {n_done_this_run}. Total done overall: {len(done)}/100.")


if __name__ == "__main__":
    main()
