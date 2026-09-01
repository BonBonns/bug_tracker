#!/usr/bin/env python3
"""NAPI-STATUS diagnostic replay over the preserved 97-bundle evidence set (review
item: replay over the existing bundles using PRESERVED facts, keeping the property
diagnostic-only).

For each preserved evidence bundle (npm_corpus/overnight_100/evidence_bundles_100/
*.tar.gz -- the same set task #34 replayed): extract the PRESERVED cpp_raw/*.tsv,
run napi_status_verdict_r02 over it, then the full integration pipeline
(napi_status_integration: enrichment -> reachability from the bundle's own preserved
cpp_facts.json/js_facts.json -> applicability -> adjudication -> DIAGNOSTIC-ONLY
enablement -> aggregate_record_r02). Emits one JSONL row per package plus a summary.

PROVENANCE MODE: bundles do not carry full source manifests; task #34 reconstructed
provenance by re-fetching each pinned tarball. This driver does the same when
--refetch is given (URL + BOTH hashes verified against the frozen sample TSV);
without it, provenance is left UNRESOLVED -- fail-closed, findings stay
non-reportable, which is fine for a diagnostic replay (and reportable would be
forced off by diagnostic-only enablement anyway).

INFRASTRUCTURE HONESTY: if the bundle directory is absent (it is a gitignored
scratch output that only exists on the machine that ran the overnight corpus pass),
this driver writes an INFRASTRUCTURE_FAILURE report and exits 3 -- an infrastructure
result, never a scanner negative and never semantic evidence, per the
pre-registered rule in study/napi_status/REAL_PACKAGE_RESULTS.md.

--selftest builds one synthetic bundle from the frozen R02 fixture facts and runs it
end to end, proving the driver mechanics wherever the real bundles are unavailable.

Usage:
  replay_napi_status_97.py [--bundle-dir DIR] [--out DIR] [--refetch] [--selftest]
"""
import argparse
import csv
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "npm_corpus"))
import napi_status_verdict_r02 as scanner  # noqa: E402
import napi_status_integration as integ  # noqa: E402
import provenance  # noqa: E402
import staged_enablement as se  # noqa: E402

DEFAULT_BUNDLE_DIR = os.path.join(_HERE, "npm_corpus", "overnight_100",
                                   "evidence_bundles_100")
SAMPLE_TSV = os.path.join(_HERE, "npm_corpus", "overnight_100",
                           "overnight_sample_100.tsv")


def load_sample_rows():
    with open(SAMPLE_TSV) as f:
        return {(r["package_name"], r["version"]): r
                for r in csv.DictReader(f, delimiter="\t")}


def process_bundle(bundle_path, refetch, sample_rows):
    with tempfile.TemporaryDirectory() as td:
        with tarfile.open(bundle_path, "r:gz") as tf:
            tf.extractall(td, filter="data")
        manifest_path = os.path.join(td, "manifest.json")
        bmanifest = json.load(open(manifest_path)) if os.path.isfile(manifest_path) \
            else {}
        pkg = bmanifest.get("package_name")
        ver = bmanifest.get("version")
        raw = os.path.join(td, "cpp_raw")
        if not os.path.isdir(raw):
            return {"package_name": pkg, "version": ver,
                    "outcome": "INFRASTRUCTURE_FAILURE",
                    "reason": "BUNDLE_HAS_NO_PRESERVED_CPP_RAW"}
        result = scanner.analyze(raw)
        record = {integ.NAPI_STATUS_KEY: result["findings"]}

        # provenance: re-fetch pinned tarball only when explicitly asked; else
        # fail-closed UNRESOLVED (diagnostic replay does not need it).
        prov_manifest = {"package_name": pkg, "version": ver,
                          "tarball_sha256": bmanifest.get("tarball_sha256"),
                          "source_tree_sha256": None, "files": {}}
        pkg_dir = "/nonexistent"
        prov_mode = "UNRESOLVED_NO_REFETCH"
        if refetch and (pkg, ver) in sample_rows:
            import hashlib
            import urllib.request
            row = sample_rows[(pkg, ver)]
            data = urllib.request.urlopen(row["tarball_url"], timeout=180).read()
            if hashlib.sha256(data).hexdigest() == row["tarball_sha256"]:
                pdir = os.path.join(td, "pkgsrc")
                os.makedirs(pdir)
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf2:
                    tf2.extractall(pdir, filter="data")
                prov_manifest = provenance.build_source_manifest(
                    pdir, data, pkg, ver)
                if prov_manifest["source_tree_sha256"] != row.get(
                        "source_tree_sha256"):
                    prov_mode = "REFETCH_TREE_HASH_MISMATCH_KEPT_UNRESOLVED"
                    prov_manifest["files"] = {}
                else:
                    pkg_dir = pdir
                    prov_mode = "REFETCHED_BOTH_HASHES_VERIFIED"
            else:
                prov_mode = "REFETCH_TARBALL_HASH_MISMATCH_KEPT_UNRESOLVED"
        unrecognized = integ.enrich_napi_status(
            record, raw, prov_manifest, pkg_dir)

        def load_json(name):
            p = os.path.join(td, name)
            try:
                return json.load(open(p)) if os.path.isfile(p) else {}
            except Exception:
                return {}
        integ.apply_napi_status_reachability(record, load_json("js_facts.json"),
                                              load_json("cpp_facts.json"))
        integ.apply_napi_status_applicability(record)
        integ.apply_napi_status_adjudications(record, pkg, ver)
        integ.enforce_napi_status_enablement(record)
        summary = integ.aggregate_record_r02(record, se.ENABLED_PROPERTIES)
        return {"package_name": pkg, "version": ver, "outcome": "ANALYZED",
                "provenance_mode": prov_mode,
                "candidate_vocabulary_unrecognized": unrecognized,
                "classification": result["classification"],
                "napi_status_summary": summary[integ.NAPI_STATUS_KEY],
                "findings": record[integ.NAPI_STATUS_KEY]}


def selftest():
    """Builds one synthetic bundle from the frozen R02 fixture facts and runs it end
    to end -- driver mechanics proven without the real (machine-local) bundles."""
    fixture_raw = os.path.join(_HERE, "study", "napi_status", "raw_synthetic_r02")
    with tempfile.TemporaryDirectory() as td:
        bdir = os.path.join(td, "bundles")
        os.makedirs(bdir)
        stage = os.path.join(td, "stage")
        shutil.copytree(fixture_raw, os.path.join(stage, "cpp_raw"))
        for name, obj in (("manifest.json", {"package_name": "selftest-pkg",
                                              "version": "0.0.0",
                                              "tarball_sha256": None}),
                          ("cpp_facts.json", {}), ("js_facts.json", {})):
            json.dump(obj, open(os.path.join(stage, name), "w"))
        bpath = os.path.join(bdir, "selftest-pkg@0.0.0.tar.gz")
        with tarfile.open(bpath, "w:gz") as tf:
            for entry in sorted(os.listdir(stage)):
                tf.add(os.path.join(stage, entry), arcname=entry)
        row = process_bundle(bpath, refetch=False, sample_rows={})
        assert row["outcome"] == "ANALYZED", row
        assert row["classification"].get("SUPPORTED_CREATION_CALL_FOUND") == 7, row
        assert row["napi_status_summary"]["reportable_count"] == 0, row
        assert row["napi_status_summary"]["enabled"] is False, row
        assert row["candidate_vocabulary_unrecognized"] == 0, row
        assert all(f.get("stage_status") == "STAGE_NOT_ENABLED_DIAGNOSTIC_ONLY"
                   for f in row["findings"]), row
        print("SELFTEST PASS: synthetic bundle analyzed end to end; "
              f"classification={row['classification']}; 0 reportable "
              "(diagnostic-only), provenance fail-closed without refetch.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle-dir", default=DEFAULT_BUNDLE_DIR)
    ap.add_argument("--out", default=os.path.join(_HERE, "study", "napi_status",
                                                    "replay_97"))
    ap.add_argument("--refetch", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        selftest()
        return

    os.makedirs(args.out, exist_ok=True)
    report_path = os.path.join(args.out, "replay_report.json")
    if not os.path.isdir(args.bundle_dir):
        report = {
            "status": "INFRASTRUCTURE_FAILURE",
            "reason": "PRESERVED_BUNDLES_ABSENT",
            "detail": (f"{args.bundle_dir} does not exist in this checkout -- the "
                        "evidence bundles are gitignored scratch outputs that only "
                        "exist on the machine that ran the overnight corpus pass. "
                        "Per the pre-registered rule this is an infrastructure "
                        "result: NOT a scanner negative and NOT semantic evidence. "
                        "Run this driver where the preserved bundles exist."),
        }
        json.dump(report, open(report_path, "w"), indent=1)
        print(json.dumps(report, indent=1))
        sys.exit(3)

    sample_rows = load_sample_rows()
    rows_out = []
    bundles = sorted(f for f in os.listdir(args.bundle_dir)
                     if f.endswith(".tar.gz"))
    for i, fn in enumerate(bundles):
        try:
            row = process_bundle(os.path.join(args.bundle_dir, fn), args.refetch,
                                  sample_rows)
        except Exception as e:
            row = {"bundle": fn, "outcome": "INFRASTRUCTURE_FAILURE",
                   "reason": f"{type(e).__name__}: {e}"}
        rows_out.append(row)
        print(f"[{i + 1}/{len(bundles)}] {fn}: {row['outcome']} "
              f"{row.get('classification') or row.get('reason')}")
    with open(os.path.join(args.out, "replay_rows.jsonl"), "w") as f:
        for row in rows_out:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    n_analyzed = sum(1 for r in rows_out if r["outcome"] == "ANALYZED")
    n_sites = sum(sum(r.get("classification", {}).values()) for r in rows_out
                  if r["outcome"] == "ANALYZED")
    report = {"status": "COMPLETE", "bundles": len(bundles),
              "analyzed": n_analyzed,
              "infrastructure_failures": len(bundles) - n_analyzed,
              "total_reportable": 0 if not integ.NAPI_STATUS_ENABLED else None,
              "note": "diagnostic-only replay: reportable is 0 by enablement design"}
    json.dump(report, open(report_path, "w"), indent=1)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
