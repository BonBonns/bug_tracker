#!/usr/bin/env python3
"""R06 persistence fix: real fixtures for evidence_bundle.py -- atomic-write validation,
disclosed missing-file accounting, cross_language_bindings extraction, and the
nothing-to-bundle case.

Run: python3 tests/test_evidence_bundle.py   (exit 0 = PASS)
"""
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from evidence_bundle import (write_evidence_bundle, BUNDLED_RELATIVE_PATHS, SCHEMA_VERSION,
                              read_bundle_manifest, require_complete_bundle,
                              IncompleteBundleError)


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond


ok = True


def make_full_work_root(root):
    work = Path(root) / "work"
    (work / "cpp_raw").mkdir(parents=True)
    (work / "cpp_raw" / "methods.tsv").write_text("1\townerid\tfoo\n")
    (work / "cpp_facts.json").write_text(json.dumps({"schema": "x", "calls": []}))
    (work / "js_facts.json").write_text(json.dumps({"schema": "y", "calls": []}))
    (work / "build_config.json").write_text(json.dumps({"exception_configuration": "disabled"}))
    (work / "r04_out.json").write_text(json.dumps({"classification": {}, "findings": []}))
    (work / "r05_out.json").write_text(json.dumps({"classification": {}, "findings": []}))
    # OVERNIGHT-DIAGNOSTIC-100: r06_out.json replaced by the five newly-wired scanners' own
    # output files -- see BUNDLED_RELATIVE_PATHS's own comment for why r06 is absent here.
    (work / "lock_balance_out.json").write_text(json.dumps({"findings": []}))
    (work / "protected_field_out.json").write_text(json.dumps({"findings": []}))
    (work / "oob_write_out.json").write_text(json.dumps({"candidates": []}))
    (work / "oob_index_write_out.json").write_text(json.dumps({"candidates": []}))
    (work / "oob_read_out.json").write_text(json.dumps({"candidates": []}))
    (work / "oob_compare_out.json").write_text(json.dumps({"candidates": []}))
    (work / "merged.json").write_text(json.dumps({
        "cross_language_bindings": {"idiom": "napi-exports-set", "registrations": [{"a": 1}],
                                     "linked_calls": [], "unlinked_calls": []}
    }))
    # These must NOT end up in the bundle -- large/regenerable, explicitly excluded.
    (work / "cpp.cpg.bin").write_bytes(b"\x00" * 4096)
    (work / "js.cpg.bin").write_bytes(b"\x00" * 4096)
    js_raw = work / "js_raw"
    js_raw.mkdir()
    (js_raw / "identifiers.tsv").write_text("1\townerid\tname\n")
    return work


# --- Fixture 1: full, real-shaped work dir -- everything expected is bundled, nothing extra ---
print('=== Fixture 1: full work dir ===')
with tempfile.TemporaryDirectory() as td:
    work_root = os.path.join(td, "pkg_root")
    make_full_work_root(work_root)
    bundle_dir = os.path.join(td, "bundles")

    path, manifest = write_evidence_bundle(work_root, bundle_dir, "some-pkg", "1.2.3")
    ok &= check("bundle path returned, file exists", path is not None and os.path.isfile(path))
    ok &= check("atomic tmp file left no trace after rename",
                not os.path.exists(os.path.join(bundle_dir, ".some-pkg@1.2.3.tar.gz.tmp")))
    ok &= check("all real facts included", set(BUNDLED_RELATIVE_PATHS) <= set(manifest["included"]),
                f"included={manifest['included']}")
    ok &= check("cross_language_bindings.json included (from merged.json)",
                "cross_language_bindings.json" in manifest["included"])
    ok &= check("nothing missing", manifest["missing"] == [], f"missing={manifest['missing']}")

    with tarfile.open(path, "r:gz") as tf:
        names = tf.getnames()
        ok &= check("cpp.cpg.bin NOT in the bundle (large, excluded)", "cpp.cpg.bin" not in names)
        ok &= check("js.cpg.bin NOT in the bundle (large, excluded)", "js.cpg.bin" not in names)
        ok &= check("js_raw/ NOT in the bundle (not currently consumed, disclosed scope boundary)",
                    not any(n.startswith("js_raw/") for n in names))
        ok &= check("merged.json NOT in the bundle (superseded by the smaller extract)",
                    "merged.json" not in names)
        ok &= check("manifest.json present inside the bundle itself", "manifest.json" in names)

        xlb_member = tf.extractfile("cross_language_bindings.json")
        xlb = json.loads(xlb_member.read())
        ok &= check("extracted cross_language_bindings has real registration data",
                    xlb.get("registrations") == [{"a": 1}], f"got {xlb}")

    ok &= check("compressed_bytes recorded and > 0", manifest.get("compressed_bytes", 0) > 0)

# --- Fixture 2: partial work dir (package failed mid-pipeline) -- missing files disclosed ---
print('=== Fixture 2: partial work dir (early failure) ===')
with tempfile.TemporaryDirectory() as td:
    work_root = os.path.join(td, "pkg_root")
    work = Path(work_root) / "work"
    work.mkdir(parents=True)
    (work / "cpp_raw").mkdir()
    (work / "cpp_raw" / "methods.tsv").write_text("1\towner\tfoo\n")
    # No cpp_facts.json, no js_facts.json, no build_config.json, no r04/r05 outputs, no merged.json.
    bundle_dir = os.path.join(td, "bundles")
    path, manifest = write_evidence_bundle(work_root, bundle_dir, "partial-pkg", "0.1.0")
    ok &= check("bundle still written for the one real thing that exists", path is not None)
    ok &= check("cpp_raw correctly included", "cpp_raw" in manifest["included"])
    ok &= check("cpp_facts.json correctly disclosed as missing, not silently skipped",
                "cpp_facts.json" in manifest["missing"])
    ok &= check("cross_language_bindings.json correctly disclosed as missing",
                "cross_language_bindings.json" in manifest["missing"])

# --- Fixture 3: nothing at all to bundle (package failed before work/ existed) ---
print('=== Fixture 3: nothing to bundle ===')
with tempfile.TemporaryDirectory() as td:
    work_root = os.path.join(td, "pkg_root")
    os.makedirs(work_root)  # work_root exists, but work/ subdir never created (e.g. DOWNLOAD_FAILED)
    bundle_dir = os.path.join(td, "bundles")
    path, manifest = write_evidence_bundle(work_root, bundle_dir, "never-started", "0.0.0")
    ok &= check("returns None, no file written", path is None and not os.listdir(bundle_dir if os.path.isdir(bundle_dir) else td))
    ok &= check("manifest reports everything missing", set(manifest["missing"]) >= set(BUNDLED_RELATIVE_PATHS))

# --- Fixture 4: package_name with a slash (scoped npm package, e.g. @cartesi/machine) ---
print('=== Fixture 4: scoped package name (contains /) ===')
with tempfile.TemporaryDirectory() as td:
    work_root = os.path.join(td, "pkg_root")
    make_full_work_root(work_root)
    bundle_dir = os.path.join(td, "bundles")
    path, manifest = write_evidence_bundle(work_root, bundle_dir, "@cartesi/machine", "1.0.0-alpha.1")
    ok &= check("scoped package name doesn't create a stray subdirectory",
                path is not None and os.path.dirname(path) == bundle_dir,
                f"got path={path}")
    ok &= check("slash replaced in the filename itself", "@cartesi__machine" in os.path.basename(path),
                f"got {os.path.basename(path)}")

# --- Fixture 5: bundle integrity fields -- schema, tarball hash, analyzer hashes, artifact
# hashes, completeness_status, for a COMPLETE (pipeline_status="ANALYZED") bundle ---
print('=== Fixture 5: integrity fields on a complete bundle ===')
with tempfile.TemporaryDirectory() as td:
    work_root = os.path.join(td, "pkg_root")
    make_full_work_root(work_root)
    bundle_dir = os.path.join(td, "bundles")
    fake_tarball_hash = "a" * 64
    path, manifest = write_evidence_bundle(work_root, bundle_dir, "some-pkg", "1.2.3",
                                            tarball_sha256=fake_tarball_hash,
                                            pipeline_status="ANALYZED")
    ok &= check("schema_version recorded", manifest.get("schema_version") == SCHEMA_VERSION)
    ok &= check("tarball_sha256 passed through", manifest.get("tarball_sha256") == fake_tarball_hash)
    ok &= check("analyzer_hashes has all real analyzer files this diagnostic run drives, none None",
                set(manifest.get("analyzer_hashes", {})) == {
                    "resource_guard_verdict_r04.py", "resource_guard_verdict_r05.py",
                    "extract_build_config.py", "evidence_bundle.py", "provenance.py",
                    "lock_balance_verdict.py", "protected_field_verdict.py",
                    "oob_write_verdict.py", "oob_index_write_verdict.py",
                    "oob_read_verdict.py", "oob_compare_verdict.py"}
                and all(manifest["analyzer_hashes"].values()),
                str(manifest.get("analyzer_hashes")))
    ok &= check("artifact_hashes has a real sha256 for every flat included file",
                all(manifest["artifact_hashes"].get(rel) for rel in
                    ("cpp_facts.json", "js_facts.json", "build_config.json",
                     "r04_out.json", "r05_out.json", "lock_balance_out.json",
                     "protected_field_out.json", "oob_write_out.json",
                     "oob_index_write_out.json", "oob_read_out.json", "oob_compare_out.json")))
    ok &= check("artifact_hashes for cpp_raw/ is a per-inner-file dict",
                isinstance(manifest["artifact_hashes"].get("cpp_raw"), dict)
                and "methods.tsv" in manifest["artifact_hashes"]["cpp_raw"])
    ok &= check("completeness_status == COMPLETE (nothing missing, status ANALYZED)",
                manifest.get("completeness_status") == "COMPLETE")

    # Loader-side guard: require_complete_bundle succeeds and returns the same manifest.
    loaded = require_complete_bundle(path)
    ok &= check("require_complete_bundle succeeds on a real complete bundle",
                loaded.get("completeness_status") == "COMPLETE")
    read_back = read_bundle_manifest(path)
    ok &= check("read_bundle_manifest round-trips the real manifest embedded in the bundle",
                read_back["package_name"] == "some-pkg"
                and read_back["completeness_status"] == "COMPLETE"
                and read_back["tarball_sha256"] == fake_tarball_hash,
                str(read_back))

# --- Fixture 6: PARTIAL bundle (real missing files, or a RESOURCE_LIMIT pipeline_status) --
# must be marked PARTIAL and require_complete_bundle must refuse it. ---
print('=== Fixture 6: partial/resource-limit bundle refused by the loader guard ===')
with tempfile.TemporaryDirectory() as td:
    work_root = os.path.join(td, "pkg_root")
    work = Path(work_root) / "work"
    work.mkdir(parents=True)
    (work / "cpp_raw").mkdir()
    (work / "cpp_raw" / "methods.tsv").write_text("1\towner\tfoo\n")
    bundle_dir = os.path.join(td, "bundles")
    path, manifest = write_evidence_bundle(work_root, bundle_dir, "limited-pkg", "0.9.0",
                                            pipeline_status="RESOURCE_LIMIT")
    ok &= check("completeness_status == PARTIAL (real files missing)",
                manifest.get("completeness_status") == "PARTIAL")
    raised = False
    try:
        require_complete_bundle(path)
    except IncompleteBundleError:
        raised = True
    ok &= check("require_complete_bundle REFUSES a partial bundle (raises, never silently returns)",
                raised)

# --- Fixture 7: a bundle with EVERY file present but pipeline_status != ANALYZED is still
# PARTIAL -- completeness is not just "nothing missing", the overall pipeline run matters too.
print('=== Fixture 7: all files present but pipeline_status != ANALYZED -> still PARTIAL ===')
with tempfile.TemporaryDirectory() as td:
    work_root = os.path.join(td, "pkg_root")
    make_full_work_root(work_root)
    bundle_dir = os.path.join(td, "bundles")
    path, manifest = write_evidence_bundle(work_root, bundle_dir, "weird-pkg", "1.0.0",
                                            pipeline_status="RESOURCE_LIMIT")
    ok &= check("nothing missing, but pipeline_status=RESOURCE_LIMIT -> PARTIAL, not COMPLETE",
                not manifest["missing"] and manifest.get("completeness_status") == "PARTIAL",
                str(manifest.get("completeness_status")))

print()
print('OVERALL:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
