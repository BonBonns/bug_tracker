#!/usr/bin/env python3
"""One-time, targeted fix: propagates the corrected npm_build_configuration.tsv row for
node-libcurl@5.1.2 (was stale "disabled"; corrected to the real, live-reproducible "enabled" --
see the TSV row's own "CORRECTED" annotation and study/resource_guard_r05/
NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md) through the frozen replay chain, producing
results/replay_records_v4.jsonl from results/replay_records_v3.jsonl.

WHY THIS IS NEEDED, NOT JUST THE TSV EDIT ALONE: replay_100_bundles.py's own real per-package
replay reruns resource_guard_verdict_r06.py FRESH against each bundle's preserved cpp_raw, but
r04_out.json/r05_out.json are read as PRESERVED bundle output (generated at the ORIGINAL overnight
scan time, under the stale build config) -- never rerun. So a TSV-only fix does not, by itself,
change one byte of results/replay_records_v3.jsonl; this script does the same targeted, preserved-
facts-only rerun replay_100_bundles.py already does for R06, applied here to BOTH R05 and R06
for node-libcurl specifically (the only package this TSV correction touches), using the corrected
build_config.json this script builds directly from the corrected TSV row -- never hand-typed,
never assumed.

Ground truth already independently confirmed twice before this script existed: (1) a direct rerun
of resource_guard_verdict_r06.py against node-libcurl's preserved cpp_raw with a corrected build
config; (2) check_provenance.py's own live central regression test, which reruns the REAL pipeline
(fresh c2cpg + joern, not preserved facts) end to end and gets the identical result for BOTH R05
and R06: verdict flips from VALUE_ACQUISITION_GUARD_MISSING to CONTRACT_NOT_APPLICABLE,
scanner_candidate flips True -> False. This script's own real rerun (preserved facts only, no
Joern rebuild, matching task #34's own discipline) is checked against that same expectation below
and aborts (fails closed) if it does not match.

No Joern rebuild. No new download of anything beyond what the narrow provenance-only exception
already re-fetched (this script reuses node-libcurl's ALREADY-established provenance fields --
source_path/content_hash/resolved -- from the existing v3 record's own r06 finding, since those
facts are about source FILE identity, entirely independent of exception_configuration, and
re-deriving them again would just re-run the exact same narrow download for no new information)."""
import json
import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
BUNDLE_DIR = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100", "evidence_bundles_100")
TSV_PATH = os.path.join(SCANNER_V2, "npm_corpus", "npm_build_configuration.tsv")

sys.path.insert(0, SCANNER_V2)
import provenance  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import applicability_gate as ag  # noqa: E402
import staged_enablement as se  # noqa: E402
import vendored_attribution as va  # noqa: E402
import six_property_aggregator as agg  # noqa: E402

PKG, VERSION = "node-libcurl", "5.1.2"


def load_corrected_build_config():
    """Reads node-libcurl's row DIRECTLY from the corrected TSV -- never hand-typed here, so a
    future edit to the TSV row is what this script picks up, not a copy of today's wording."""
    with open(TSV_PATH) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if parts[idx["package_name"]] == PKG and parts[idx["version"]] == VERSION:
                exc = parts[idx["exception_configuration"]]
                enable_ev = parts[idx["enable_evidence"]] if "enable_evidence" in idx else ""
                assert exc == "enabled", (
                    f"TSV row for {PKG}@{VERSION} is {exc!r}, not the expected corrected "
                    f"'enabled' -- refusing to proceed; this script only ever propagates the "
                    f"CORRECTED value, never assumes it")
                return {
                    "exception_configuration": exc,
                    "evidence": [{"note": enable_ev}] if enable_ev else [],
                    "citation": "npm_build_configuration.tsv (corrected row) + "
                                 "study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md",
                }
    raise RuntimeError(f"{PKG}@{VERSION} not found in {TSV_PATH}")


def rerun_r0x(script_name, cpp_raw_dir, build_config_path, work_dir):
    out_path = os.path.join(work_dir, f"_{script_name}_out.json")
    rc = subprocess.run(
        [sys.executable, os.path.join(SCANNER_V2, script_name),
         cpp_raw_dir, out_path, "--real", "--build-config", build_config_path],
        capture_output=True, text=True, timeout=300)
    if rc.returncode != 0:
        raise RuntimeError(f"{script_name} failed: {rc.stderr[-2000:]}")
    return json.load(open(out_path)).get("findings", [])


def reuse_provenance(new_finding, old_findings_by_method):
    """Reuses the ALREADY-resolved provenance dict from the matching old (v3) finding at the
    same method_id -- provenance is about source file identity, never about exception
    configuration, so re-deriving it would just repeat the same narrow download for no new
    information. Fails closed (leaves provenance unresolved) if no match is found, rather than
    guessing."""
    old = old_findings_by_method.get(new_finding.get("method_id"))
    if old and old.get("provenance", {}).get("resolved"):
        new_finding["provenance"] = dict(old["provenance"])
    else:
        new_finding["provenance"] = {"resolved": False,
                                       "reason": "NO_MATCHING_V3_PROVENANCE_TO_REUSE"}
    return new_finding


def main():
    build_config = load_corrected_build_config()

    bundle_path = os.path.join(BUNDLE_DIR, f"{PKG}@{VERSION}.tar.gz")
    if not os.path.isfile(bundle_path):
        raise RuntimeError(f"bundle missing: {bundle_path}")

    work_dir = tempfile.mkdtemp(prefix="libcurl_regression_fix_")
    with tarfile.open(bundle_path, "r:gz") as tf:
        tf.extractall(work_dir)  # trusted, already-verified local bundle -- same discipline as
                                   # replay_100_bundles.py's own safe_extract_tar for this bundle
    cpp_raw_dir = os.path.join(work_dir, "cpp_raw")

    build_config_path = os.path.join(work_dir, "build_config_corrected.json")
    with open(build_config_path, "w") as f:
        json.dump(build_config, f)

    new_r05 = rerun_r0x("resource_guard_verdict_r05.py", cpp_raw_dir, build_config_path, work_dir)
    new_r06 = rerun_r0x("resource_guard_verdict_r06.py", cpp_raw_dir, build_config_path, work_dir)

    # --- fail-closed expectation check: this is a KNOWN, already-independently-confirmed result,
    #     never assumed to hold again silently ------------------------------------------------
    r05_rf = [f for f in new_r05 if f.get("method_name") == "ReadFunction"]
    r06_rf = [f for f in new_r06 if f.get("method_name") == "ReadFunction"]
    assert len(r05_rf) == 1 and r05_rf[0]["verdict"] == "CONTRACT_NOT_APPLICABLE", (
        f"EXPECTATION MISMATCH: R05 ReadFunction verdict is not the expected corrected "
        f"CONTRACT_NOT_APPLICABLE ({r05_rf!r}) -- aborting, not writing v4")
    assert len(r06_rf) == 1 and r06_rf[0]["verdict"] == "CONTRACT_NOT_APPLICABLE", (
        f"EXPECTATION MISMATCH: R06 ReadFunction verdict is not the expected corrected "
        f"CONTRACT_NOT_APPLICABLE ({r06_rf!r}) -- aborting, not writing v4")

    v3_path = os.path.join(RESULTS_DIR, "replay_records_v3.jsonl")
    v4_path = os.path.join(RESULTS_DIR, "replay_records_v4.jsonl")
    if os.path.exists(v4_path):
        os.remove(v4_path)

    patched = False
    delta = {"package": f"{PKG}@{VERSION}", "r05_before": None, "r05_after": None,
             "r06_before": None, "r06_after": None}

    with open(v3_path) as fin, open(v4_path, "a") as fout:
        for line in fin:
            rec = json.loads(line)
            if rec.get("package_name") == PKG and rec.get("version") == VERSION:
                old_r05_by_method = {f.get("method_id"): f for f in (rec.get("r05_findings") or [])}
                old_r06_by_method = {f.get("method_id"): f for f in (rec.get("r06_findings") or [])}
                old_r05_rf = next((f for f in (rec.get("r05_findings") or [])
                                    if f.get("method_name") == "ReadFunction"), None)
                old_r06_rf = next((f for f in (rec.get("r06_findings") or [])
                                    if f.get("method_name") == "ReadFunction"), None)
                delta["r05_before"] = {"verdict": old_r05_rf.get("verdict") if old_r05_rf else None,
                                        "scanner_candidate": old_r05_rf.get("scanner_candidate") if old_r05_rf else None,
                                        "reportable": old_r05_rf.get("reportable") if old_r05_rf else None}
                delta["r06_before"] = {"verdict": old_r06_rf.get("verdict") if old_r06_rf else None,
                                        "applicability_status": old_r06_rf.get("applicability_status") if old_r06_rf else None,
                                        "adjudication_status": old_r06_rf.get("adjudication_status") if old_r06_rf else None,
                                        "reportable": old_r06_rf.get("reportable") if old_r06_rf else None}

                for f in new_r05:
                    reuse_provenance(f, old_r05_by_method)
                    provenance.finalize_reportability(
                        f, provenance.PROPERTY_CANDIDATE_RULES["r05_findings"](f))
                for f in new_r06:
                    reuse_provenance(f, old_r06_by_method)
                    provenance.finalize_reportability(
                        f, provenance.PROPERTY_CANDIDATE_RULES["r06_findings"](f))
                    # reachability_status: R06 findings never entered the applicability/staged
                    # path via reachability_tier (Resource Guard's own applicability rule never
                    # reads it -- only the five staged properties do); left absent, same as v3.

                rec["r05_findings"] = new_r05
                rec["r06_findings"] = new_r06

                # re-run the SAME downstream chain rerun_aggregator_applicability.py already
                # established for v2->v3, over this one corrected record, so v4 stays internally
                # consistent (applicability -> adjudication -> staged_enablement ->
                # vendored_attribution -> six_property_aggregator), not just a raw-verdict patch.
                ag.apply_applicability(rec)
                ar.apply_known_adjudications(rec)
                se.enforce_staged_enablement(rec)
                va.attribute_record(rec)
                rec["_six_property_summary"] = agg.aggregate_record(
                    rec, enabled_properties=se.ENABLED_PROPERTIES)
                rec["_libcurl_build_config_regression_fix"] = (
                    "r05_findings/r06_findings regenerated against preserved cpp_raw with the "
                    "corrected npm_build_configuration.tsv row (was stale 'disabled', corrected "
                    "to 'enabled') -- no Joern rebuild, no new download; provenance reused from "
                    "the existing v3 record's own already-resolved fields")

                new_r05_rf = next((f for f in new_r05 if f.get("method_name") == "ReadFunction"), None)
                new_r06_rf = next((f for f in new_r06 if f.get("method_name") == "ReadFunction"), None)
                delta["r05_after"] = {"verdict": new_r05_rf.get("verdict"),
                                       "scanner_candidate": new_r05_rf.get("scanner_candidate"),
                                       "reportable": new_r05_rf.get("reportable")}
                delta["r06_after"] = {"verdict": new_r06_rf.get("verdict"),
                                       "applicability_status": new_r06_rf.get("applicability_status"),
                                       "adjudication_status": new_r06_rf.get("adjudication_status"),
                                       "reportable": new_r06_rf.get("reportable")}
                patched = True
            fout.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    if not patched:
        raise RuntimeError(f"{PKG}@{VERSION} not found in {v3_path} -- v4 not written correctly")

    with open(os.path.join(RESULTS_DIR, "libcurl_build_config_regression_fix_delta.json"), "w") as f:
        json.dump(delta, f, indent=2, sort_keys=True, default=str)

    print("node-libcurl build-config regression fix applied. Delta:")
    print(json.dumps(delta, indent=2, default=str))
    print(f"Wrote {v4_path}")


if __name__ == "__main__":
    main()
