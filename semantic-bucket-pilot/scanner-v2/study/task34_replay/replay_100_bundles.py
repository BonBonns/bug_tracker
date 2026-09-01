#!/usr/bin/env python3
"""TASK34-REPLAY-R01: replays the 100 preserved overnight-diagnostic-100 evidence bundles
through the completed post-scan logic (provenance -> vendored attribution -> reachability tier
-> staged enablement -> R06 Resource Guard -> six-property aggregation) and produces one
combined, fail-closed record per package.

NOT a new corpus run: no Joern is invoked, no CPG is rebuilt, no C/C++/JS facts are
regenerated. The only new computation over PRESERVED evidence is resource_guard_verdict_r06.py,
run fresh over each bundle's own already-extracted cpp_raw/*.tsv (item 1's own requirement --
these bundles predate R06's wiring into run_pipeline_one.py, so no r06_out.json was ever
captured for them).

PROVENANCE_SOURCE_DECISION (explicit instruction, amending the replay's own no-download default):
no evidence bundle preserves per-file source bytes (evidence_bundle.py's own module docstring:
pkg/, the extracted npm source, is deliberately excluded -- "cheaply re-fetchable... if ever
needed again"). provenance.py's content_hash is a sha256 of one specific source file's own real
bytes; without it, provenance.resolved is False for every finding by construction, which cascades
into vendored_attribution.py never attributing anything (attribute_finding() requires
resolved=True) -- making reportable and vendored-dedup structurally degenerate rather than a real
replay result. Direct instruction: re-fetch ONLY the 97 exact pinned tarball URLs already
recorded by the frozen run (npm_corpus/overnight_100/overnight_sample_100.json), hash-verify the
downloaded bytes against the frozen tarball_sha256 BEFORE extraction, hash-verify the recomputed
source_tree_sha256 against the frozen value AFTER extraction, trust per-file bytes only when BOTH
checks pass, and delete the extracted source immediately after provenance enrichment. This is
re-fetching pinned bytes to reconstruct missing provenance evidence, not a new scan: no Joern
stage, no facts regeneration, no scanner rerun consumes the downloaded source -- every scanner
input (cpp_raw/, cpp_facts.json, js_facts.json, build_config.json, and every *_out.json except
r06) comes from the PRESERVED bundle, unchanged.

Usage: python3 replay_100_bundles.py [--limit N] [--only PKG@VERSION,...]
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
OVERNIGHT_DIR = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100")
BUNDLE_DIR = os.path.join(OVERNIGHT_DIR, "evidence_bundles_100")
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, os.path.join(SCANNER_V2, "npm_corpus"))

import provenance  # noqa: E402
import reachability_tier as rt  # noqa: E402
import staged_enablement as se  # noqa: E402
import six_property_aggregator as agg  # noqa: E402
import vendored_attribution as va  # noqa: E402
import evidence_bundle as eb  # noqa: E402

DEVELOP_COMMIT = "fdb22fa5af01cbaab9577d85906f0a33515f0e62"  # develop @ the commit this replay
                                                                # runs against -- recorded, not
                                                                # re-derived from git at run time
                                                                # so the record is self-contained.

# The exact analyzer files this replay's own logic depends on, hashed fresh at run time (never
# reused from a bundle's own analyzer_hashes, which recorded an EARLIER revision of some of
# these -- e.g. no bundle's analyzer_hashes includes resource_guard_verdict_r06.py at all, since
# these bundles predate its wiring).
DRIVEN_ANALYZER_FILES = [
    "provenance.py", "reachability_tier.py", "staged_enablement.py",
    "six_property_aggregator.py", "vendored_attribution.py",
    "resource_guard_verdict_r06.py",
    os.path.join("npm_corpus", "evidence_bundle.py"),
    os.path.join("npm_corpus", "extract_build_config.py"),
]

OUT_JSON_TO_RECORD_KEY = {
    "r04_out.json": ("findings", "r04_findings"),
    "r05_out.json": ("findings", "r05_findings"),
    "lock_balance_out.json": ("findings", "lock_balance_findings"),
    "protected_field_out.json": ("findings", "protected_field_findings"),
    "oob_write_out.json": ("candidates", "oob_write_candidates"),
    "oob_index_write_out.json": ("candidates", "oob_index_write_candidates"),
    "oob_read_out.json": ("candidates", "oob_read_candidates"),
    "oob_compare_out.json": ("candidates", "oob_compare_candidates"),
}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def bundle_filename(pkg_name, version):
    return f"{pkg_name.replace('/', '__')}@{version}.tar.gz"


# =====================================================================================
# STEP 1: identity-level reconciliation (frozen manifest vs. bundle directory) -- verified by
# direct instruction BEFORE any replay work: bundle identities must equal ANALYZED identities,
# exactly, and the 3 missing identities must equal CPP_CPG_FAILED ∪ EXPORT_FAILED, exactly. Any
# mismatch is a real evidence-preservation discrepancy and STOPS the replay.
# =====================================================================================
def load_frozen_manifest():
    records_by_status = {}
    all_records = {}
    with open(os.path.join(OVERNIGHT_DIR, "overnight_diagnostic_working.jsonl")) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            key = (d.get("package_name"), d.get("version"))
            all_records[key] = d
            records_by_status.setdefault(d.get("status"), set()).add(key)
    with open(os.path.join(OVERNIGHT_DIR, "overnight_sample_100.json")) as f:
        sample = json.load(f)
    sample_by_key = {(p["package_name"], p["version"]): p for p in sample["packages"]}
    return all_records, records_by_status, sample_by_key


def reconcile_identities(all_records, records_by_status, sample_by_key):
    """Returns (ok: bool, report: dict). Never proceeds to replay if ok is False."""
    identities_100 = set(all_records)
    analyzed = records_by_status.get("ANALYZED", set())
    cpp_cpg_failed = records_by_status.get("CPP_CPG_FAILED", set())
    export_failed = records_by_status.get("EXPORT_FAILED", set())
    other_statuses = {s: v for s, v in records_by_status.items()
                       if s not in ("ANALYZED", "CPP_CPG_FAILED", "EXPORT_FAILED")}

    bundle_files = sorted(f for f in os.listdir(BUNDLE_DIR) if f.endswith(".tar.gz"))

    def parse_bundle_filename(fn):
        base = fn[:-len(".tar.gz")]
        at = base.rfind("@")
        return (base[:at].replace("__", "/"), base[at + 1:])

    bundle_identities = set(parse_bundle_filename(f) for f in bundle_files)
    expected_missing = cpp_cpg_failed | export_failed

    report = {
        "total_frozen_identities": len(identities_100),
        "analyzed_count": len(analyzed),
        "cpp_cpg_failed_count": len(cpp_cpg_failed),
        "export_failed_count": len(export_failed),
        "other_status_counts": {k: len(v) for k, v in other_statuses.items()},
        "bundle_file_count": len(bundle_files),
        "bundle_identities_equal_analyzed": bundle_identities == analyzed,
        "unexpected_extra_bundles": sorted(f"{p}@{v}" for p, v in (bundle_identities - analyzed)),
        "analyzed_missing_bundle": sorted(f"{p}@{v}" for p, v in (analyzed - bundle_identities)),
        "missing_matches_cpp_cpg_failed_union_export_failed":
            (identities_100 - bundle_identities) == expected_missing,
    }
    report["inherited_failures"] = sorted(
        [{"package_name": p, "version": v, "status": all_records[(p, v)]["status"],
          "detail": all_records[(p, v)].get("detail")}
         for (p, v) in (identities_100 - bundle_identities)],
        key=lambda r: (r["package_name"], r["version"]))

    ok = (report["bundle_identities_equal_analyzed"]
          and report["missing_matches_cpp_cpg_failed_union_export_failed"]
          and not other_statuses
          and len(identities_100) == 100)
    return ok, report


# =====================================================================================
# STEP 2: per-package replay
# =====================================================================================
class ReplayFailure(Exception):
    def __init__(self, reason, detail):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


def verify_bundle_internal_integrity(bundle_path, manifest, scratch_dir):
    """Re-hashes every file the bundle's own artifact_hashes records, from the ALREADY-EXTRACTED
    bundle contents (no download) -- a real corruption check independent of the original npm
    tarball. Raises ReplayFailure on any mismatch."""
    artifact_hashes = manifest.get("artifact_hashes", {})
    for relname, expected in artifact_hashes.items():
        if isinstance(expected, dict):
            for inner_name, inner_hash in expected.items():
                p = os.path.join(scratch_dir, relname, inner_name)
                if not os.path.isfile(p):
                    raise ReplayFailure("BUNDLE_INTERNAL_INTEGRITY_FAILED",
                                         f"missing {relname}/{inner_name}")
                got = sha256_file(p)
                if got != inner_hash:
                    raise ReplayFailure("BUNDLE_INTERNAL_INTEGRITY_FAILED",
                                         f"{relname}/{inner_name}: expected {inner_hash} got {got}")
        else:
            p = os.path.join(scratch_dir, relname)
            if not os.path.isfile(p):
                raise ReplayFailure("BUNDLE_INTERNAL_INTEGRITY_FAILED", f"missing {relname}")
            got = sha256_file(p)
            if got != expected:
                raise ReplayFailure("BUNDLE_INTERNAL_INTEGRITY_FAILED",
                                     f"{relname}: expected {expected} got {got}")


def safe_extract_tar(tf, dest):
    """Extracts a tarball guarding against path traversal (a member escaping dest via '..' or an
    absolute path) -- npm tarballs are not adversarial in this context, but a re-fetched archive
    is still untrusted input until this check passes."""
    dest_abs = os.path.abspath(dest)
    for member in tf.getmembers():
        member_path = os.path.abspath(os.path.join(dest, member.name))
        if not (member_path == dest_abs or member_path.startswith(dest_abs + os.sep)):
            raise ReplayFailure("TAR_PATH_TRAVERSAL", member.name)
    tf.extractall(dest)


def download_and_verify_source(pkg_name, version, tarball_url, expected_tarball_sha256,
                                 expected_source_tree_sha256, work_dir, timing):
    """Implements the user's own explicit 10-point procedure: download -> verify tarball bytes
    -> safe-extract -> verify source_tree_sha256 -> build the real per-file provenance manifest.
    Returns (real_manifest_dict_or_None, provenance_source_str, tarball_verified, tree_verified,
    failure_detail_or_None). Never fabricates a manifest on a failed check -- returns None,
    forcing the caller to fall through to the existing, correct unresolved-provenance path."""
    t0 = time.time()
    tgz_path = os.path.join(work_dir, "_refetched.tgz")
    last_err = None
    for attempt, delay in enumerate((0, 2, 4, 8, 16)):
        if delay:
            time.sleep(delay)
        try:
            req = urllib.request.Request(tarball_url, headers={"User-Agent": "task34-replay/1"})
            with urllib.request.urlopen(req, timeout=60) as resp, open(tgz_path, "wb") as out:
                shutil.copyfileobj(resp, out)
            last_err = None
            break
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last_err = str(e)
    timing["download_seconds"] = time.time() - t0
    if last_err is not None:
        return None, "REFETCH_DOWNLOAD_FAILED", False, False, last_err

    with open(tgz_path, "rb") as f:
        tarball_bytes = f.read()
    got_tarball_hash = sha256_bytes(tarball_bytes)
    tarball_verified = got_tarball_hash == expected_tarball_sha256
    if not tarball_verified:
        return None, "REFETCH_TARBALL_HASH_MISMATCH", False, False, (
            f"expected {expected_tarball_sha256} got {got_tarball_hash}")

    extract_dir = os.path.join(work_dir, "pkg_src")
    os.makedirs(extract_dir, exist_ok=True)
    t0 = time.time()
    try:
        with tarfile.open(tgz_path, "r:gz") as tf:
            safe_extract_tar(tf, extract_dir)
    except (tarfile.TarError, ReplayFailure) as e:
        return None, "REFETCH_EXTRACT_FAILED", tarball_verified, False, str(e)
    timing["extract_seconds"] = time.time() - t0

    # npm tarballs conventionally nest everything under a single top-level 'package/' dir --
    # provenance.build_source_manifest walks whatever pkg_dir it's given, so point it at that
    # real root (matching what the ORIGINAL scan-time extraction used), not the wrapper dir.
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    pkg_dir = os.path.join(extract_dir, "package") if "package" in entries else extract_dir

    t0 = time.time()
    real_manifest = provenance.build_source_manifest(pkg_dir, tarball_bytes, pkg_name, version)
    timing["hash_seconds"] = time.time() - t0
    tree_verified = real_manifest["source_tree_sha256"] == expected_source_tree_sha256
    if not tree_verified:
        return None, "REFETCH_SOURCE_TREE_HASH_MISMATCH", tarball_verified, False, (
            f"expected {expected_source_tree_sha256} got {real_manifest['source_tree_sha256']}")

    return real_manifest, "REFETCHED_PINNED_TARBALL", True, True, None


def replay_one_package(pkg_name, version, sample_info, timing_out):
    """Full per-package replay. Returns the combined record dict. Raises ReplayFailure for a
    genuinely unrecoverable case (corrupt bundle, bundle missing); a download/hash-verification
    failure is NOT raised here -- it is recorded on the record itself (provenance stays
    unresolved for that package, per direct instruction) and replay continues."""
    bpath = os.path.join(BUNDLE_DIR, bundle_filename(pkg_name, version))
    if not os.path.isfile(bpath):
        raise ReplayFailure("BUNDLE_FILE_MISSING", bpath)

    t_total0 = time.time()
    manifest = eb.require_complete_bundle(bpath)  # raises IncompleteBundleError if not COMPLETE

    work_dir = tempfile.mkdtemp(prefix="task34_replay_")
    try:
        t0 = time.time()
        with tarfile.open(bpath, "r:gz") as tf:
            safe_extract_tar(tf, work_dir)
        timing_out["bundle_extract_seconds"] = time.time() - t0

        verify_bundle_internal_integrity(bpath, manifest, work_dir)

        cpp_raw_dir = os.path.join(work_dir, "cpp_raw")
        build_config_path = os.path.join(work_dir, "build_config.json")
        js_facts = json.load(open(os.path.join(work_dir, "js_facts.json")))
        cpp_facts = json.load(open(os.path.join(work_dir, "cpp_facts.json")))

        # --- item 1: run R06 fresh over PRESERVED cpp_raw (never rerun over refetched source) --
        r06_out_path = os.path.join(work_dir, "r06_out.json")
        t0 = time.time()
        r06_rc = subprocess.run(
            [sys.executable, os.path.join(SCANNER_V2, "resource_guard_verdict_r06.py"),
             cpp_raw_dir, r06_out_path, "--real", "--build-config", build_config_path],
            capture_output=True, text=True, timeout=300)
        timing_out["r06_scan_seconds"] = time.time() - t0
        if r06_rc.returncode != 0:
            raise ReplayFailure("R06_SCAN_FAILED", r06_rc.stderr[-2000:])
        r06_doc = json.load(open(r06_out_path))

        record = {"package_name": pkg_name, "version": version, "r06_findings": r06_doc.get("findings", [])}
        for fname, (list_key, record_key) in OUT_JSON_TO_RECORD_KEY.items():
            p = os.path.join(work_dir, fname)
            doc = json.load(open(p)) if os.path.isfile(p) else {}
            record[record_key] = doc.get(list_key, [])

        # --- refetch-and-verify pinned source, per direct instruction -----------------------
        real_manifest, prov_source, tarball_ok, tree_ok, fail_detail = download_and_verify_source(
            pkg_name, version, sample_info["tarball_url"],
            sample_info["tarball_sha256"], sample_info["source_tree_sha256"],
            work_dir, timing_out)

        if real_manifest is not None:
            manifest_for_enrich = {
                "package_name": pkg_name, "version": version,
                "tarball_sha256": sample_info["tarball_sha256"],
                "source_tree_sha256": sample_info["source_tree_sha256"],
                "files": real_manifest["files"],
            }
            pkg_dir_for_enrich = ""  # only used for absolute-path normalization; raw c2cpg
                                      # filename fields are already relative in this corpus.
        else:
            # per direct instruction #9: keep provenance unresolved, never substitute metadata.
            manifest_for_enrich = {
                "package_name": pkg_name, "version": version,
                "tarball_sha256": sample_info["tarball_sha256"],
                "source_tree_sha256": sample_info["source_tree_sha256"],
                "files": {},
            }
            pkg_dir_for_enrich = ""

        provenance.enrich_record(record, cpp_raw_dir, manifest_for_enrich, pkg_dir_for_enrich)
        rt.classify_record_reachability(record, js_facts, cpp_facts)
        se.enforce_staged_enablement(record)
        va.attribute_record(record)
        summary = agg.aggregate_record(record, enabled_properties=se.ENABLED_PROPERTIES)

        record["_provenance_source"] = prov_source
        record["_tarball_hash_verified"] = tarball_ok
        record["_source_tree_hash_verified"] = tree_ok
        record["_refetch_failure_detail"] = fail_detail
        record["_six_property_summary"] = summary
        record["_bundle_manifest"] = {
            "schema_version": manifest.get("schema_version"),
            "completeness_status": manifest.get("completeness_status"),
            "pipeline_status": manifest.get("pipeline_status"),
            "bundle_tarball_sha256": manifest.get("tarball_sha256"),
            "bundle_artifact_hashes_verified": True,  # verify_bundle_internal_integrity()
                                                        # already raised above if not.
            "bundle_analyzer_hashes_at_capture_time": manifest.get("analyzer_hashes"),
        }
        record["_timing"] = dict(timing_out)
        record["_total_seconds"] = time.time() - t_total0
        record["_develop_commit"] = DEVELOP_COMMIT
        return record
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)  # deletes refetched source immediately,
                                                        # per direct instruction #8.


if __name__ == "__main__":
    print("This module is imported by run_replay.py -- see that file for the actual driver.")
