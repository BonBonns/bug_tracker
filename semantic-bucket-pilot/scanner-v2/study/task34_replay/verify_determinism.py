#!/usr/bin/env python3
"""TASK34-DETERMINISM-R01: independently re-runs the full 97-package replay a second time and
compares a semantic digest of each package's record against the first run -- performs the actual
rerun-and-digest-comparison rather than asserting reproducibility from design alone.

Semantic digest = sha256 of the record's own JSON (sorted keys) with non-deterministic/wall-
clock-only fields removed first (_timing, _total_seconds -- real measurements that legitimately
vary run to run without changing any finding, verdict, or reportable value). Two runs producing
identical digests for all 97 packages is real, observed evidence of determinism, not a claim
about it.
"""
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, HERE)
import replay_100_bundles as R  # noqa: E402

NON_DETERMINISTIC_FIELDS = {"_timing", "_total_seconds"}


def semantic_digest(record):
    stripped = {k: v for k, v in record.items() if k not in NON_DETERMINISTIC_FIELDS}
    blob = json.dumps(stripped, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def load_original_digests():
    digests = {}
    with open(os.path.join(RESULTS_DIR, "replay_records.jsonl")) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if d.get("outcome") == "REPLAYED":
                key = (d["package_name"], d["version"])
                digests[key] = semantic_digest(d)
    return digests


def main():
    all_records, records_by_status, sample_by_key = R.load_frozen_manifest()
    original_digests = load_original_digests()
    analyzed = sorted(records_by_status["ANALYZED"])
    assert set(analyzed) == set(original_digests), (
        f"package set mismatch: {set(analyzed) ^ set(original_digests)}")

    mismatches = []
    rerun_failures = []
    n_ok = 0
    t0 = time.time()
    for i, (pkg_name, version) in enumerate(analyzed, 1):
        sample_info = sample_by_key[(pkg_name, version)]
        timing = {}
        try:
            record = R.replay_one_package(pkg_name, version, sample_info, timing)
        except Exception as e:
            rerun_failures.append({"package_name": pkg_name, "version": version,
                                    "error": f"{type(e).__name__}: {e}"})
            print(f"[{i}/97] {pkg_name}@{version}: RERUN FAILED ({type(e).__name__}: {e})")
            continue
        record["outcome"] = "REPLAYED"
        new_digest = semantic_digest(record)
        old_digest = original_digests[(pkg_name, version)]
        if new_digest == old_digest:
            n_ok += 1
            print(f"[{i}/97] {pkg_name}@{version}: MATCH ({new_digest[:12]}...)")
        else:
            mismatches.append({"package_name": pkg_name, "version": version,
                                "original_digest": old_digest, "rerun_digest": new_digest})
            print(f"[{i}/97] {pkg_name}@{version}: *** MISMATCH *** "
                  f"orig={old_digest[:12]} rerun={new_digest[:12]}")

    result = {
        "total_packages": len(analyzed),
        "matched": n_ok,
        "mismatched": len(mismatches),
        "rerun_failures": len(rerun_failures),
        "mismatches": mismatches,
        "rerun_failure_detail": rerun_failures,
        "elapsed_seconds": round(time.time() - t0, 1),
        "all_deterministic": len(mismatches) == 0 and len(rerun_failures) == 0,
    }
    with open(os.path.join(RESULTS_DIR, "determinism_verification.json"), "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
    print(f"\nDETERMINISM VERIFICATION: {n_ok}/{len(analyzed)} matched, "
          f"{len(mismatches)} mismatched, {len(rerun_failures)} rerun failures.")
    print("ALL DETERMINISTIC" if result["all_deterministic"] else "NOT FULLY DETERMINISTIC")


if __name__ == "__main__":
    main()
