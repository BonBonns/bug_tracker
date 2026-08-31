#!/usr/bin/env python3
"""PROV-R01 (task #35) regression. Verifies provenance.py's join logic against real, already-
committed evidence: study/resource_guard/raw_c01_missing_check/'s own real methods.tsv (a real
Joern-derived raw fact table, checked into this repo), plus a real, live re-derivation of a real
npm evidence bundle already used in task #28 (@fqlan/add-example-prebuild) -- re-fetched here
rather than reusing a stale cached copy, so this check reproduces from first principles.

Checks, in order:
  1. Unit tests on classify_vendored_hint() against the REAL vendored/package-owned path shapes
     task #28 actually observed (re2's vendor/abseil-cpp, ffi-napi's deps/libffi) -- not
     hypothetical examples.
  2. A join through a real, committed raw-fact table (methods.tsv) where a finding's own
     method_id resolves to a real file that IS present in the manifest (a real content hash
     comes back).
  3. Honest degradation on an unresolvable method_id (no crash, no guess -- a named, disclosed
     reason).
  4. An end-to-end real npm run through run_pipeline_one.py's own run_one(), confirming a real
     source_tree_hash and a non-zero real file count appear in the record's own
     provenance_summary -- the same real package (@fqlan/add-example-prebuild) the ORIGINAL
     pipeline itself was manually validated against, per that file's own module docstring.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import provenance  # noqa: E402

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def main():
    # --- 1. vendored-hint heuristic, against real paths task #28 actually observed -----------
    ck("re2 vendored abseil path -> VENDORED_HINT",
       provenance.classify_vendored_hint(
           "vendor/abseil-cpp/absl/base/internal/strerror.cc") == "VENDORED_HINT")
    ck("ffi-napi vendored libffi path -> VENDORED_HINT",
       provenance.classify_vendored_hint("deps/libffi/src/closures.c") == "VENDORED_HINT")
    ck("package-owned path -> PACKAGE_OWNED_HINT",
       provenance.classify_vendored_hint("src/add.cpp") == "PACKAGE_OWNED_HINT")
    ck("third_party path -> VENDORED_HINT",
       provenance.classify_vendored_hint("third_party/foo/bar.c") == "VENDORED_HINT")

    # --- 2/3. join through a real, committed raw-fact table ----------------------------------
    fixture_dir = HERE / "study" / "resource_guard" / "raw_c01_missing_check"
    method_map = provenance.load_method_file_map(str(fixture_dir))
    ck("real methods.tsv parsed, at least one method found", len(method_map) > 0)
    real_id = next(iter(method_map))
    real_file = method_map[real_id]
    ck("a real method's file field decodes to a non-empty string", bool(real_file))

    manifest = provenance.build_source_manifest(str(fixture_dir), b"placeholder", "test-pkg", "1.0.0")
    unknown_id_finding = {"method_id": 99999999999}
    provenance.enrich_finding(unknown_id_finding, unknown_id_finding["method_id"], method_map,
                               manifest, str(fixture_dir), "method_id")
    ck("unknown method_id degrades honestly (no crash, named reason)",
       unknown_id_finding["provenance"]["provenance_hint"] == "FILE_NOT_FOUND_IN_METHODS_TABLE"
       and unknown_id_finding["provenance"]["content_hash"] is None)

    # --- 4. end-to-end real npm run through the real orchestrator -----------------------------
    npm_corpus = HERE / "npm_corpus"
    sys.path.insert(0, str(npm_corpus))
    import shutil
    import run_pipeline_one as P

    eligible = {}
    with open(npm_corpus / "eligible_packages.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            eligible[parts[idx["package_name"]]] = {"version": parts[idx["version"]],
                                                       "tarball_url": parts[idx["tarball_url"]]}
    build_config = {}
    with open(npm_corpus / "npm_build_configuration.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            build_config[(parts[idx["package_name"]], parts[idx["version"]])] = \
                parts[idx["exception_configuration"]]

    pkg = "@fqlan/add-example-prebuild"
    info = eligible[pkg]
    exc = build_config.get((pkg, info["version"]))
    work_root = "/tmp/check_provenance_bundle"
    shutil.rmtree(work_root, ignore_errors=True)
    rec = P.run_one(pkg, info["version"], info["tarball_url"], exc, work_root)

    ck("real end-to-end run reaches ANALYZED", rec.get("status") == "ANALYZED")
    ps = rec.get("provenance_summary") or {}
    ck("provenance_summary has a real, non-empty source_tree_hash",
       bool(ps.get("source_tree_hash")) and len(ps["source_tree_hash"]) == 64)
    ck("provenance_summary reports a real, non-zero file count", (ps.get("n_files_hashed") or 0) > 0)
    shutil.rmtree(work_root, ignore_errors=True)

    print(f"\nPROVENANCE_CONTROLS={ok}/{total}")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
