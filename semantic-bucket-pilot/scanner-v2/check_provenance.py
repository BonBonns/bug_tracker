#!/usr/bin/env python3
"""PROV-R01 (task #35) regression. Verifies provenance.py's join logic end to end, against real
evidence only -- no synthetic manifests standing in for a real positive finding.

Checks, in order:
  1. classify_vendored_hint() against the REAL vendored/package-owned path shapes task #28
     actually observed (re2's vendor/abseil-cpp, ffi-napi's deps/libffi).
  2. tarball_sha256 vs. source_tree_sha256 are REAL, DISTINCT hashes, and source_tree_sha256 is
     deterministic and reproducible independent of the tarball's own bytes (same file content +
     layout -> same source_tree_sha256 even with different tarball bytes wrapping it).
  3. Fail-closed degradation: an unresolvable node_id produces actionable=False (never silently
     treated as resolved); a real resolved finding produces actionable=True.
  4. A REAL POSITIVE Resource Guard (R04/R05) diagnostic: node-libcurl@5.1.2's own real
     Easy::ReadFunction / VALUE_ACQUISITION_GUARD_MISSING finding (the one real finding the
     frozen R04/R05 pipeline ever produced across the full 452-package corpus scan, per
     R05_CORPUS_RESULTS.md) is reproduced fresh through run_pipeline_one.py's real orchestrator,
     and its own enriched provenance (source_path, content_hash, both tree hashes, method_id) is
     checked against the real source file directly -- not just "did enrichment run without
     crashing."
  5. A REAL POSITIVE LOCK_BALANCE diagnostic: the real, committed wolfSSL vulnerable fixture
     (study/lockcap/raw_real_vuln/fixture_source.c, CVE-2026-5264), rebuilt fresh through c2cpg
     (not the stale committed raw facts, which use a different original filename), run through
     lock_balance_verdict.py, enriched, and checked against the real source file.
  6. The same for PROTECTED_FIELD, using study/lockcap/raw_xfn_real/fixture_source.c
     (case_644b3e3c).
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import provenance  # noqa: E402

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
CPP_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def build_single_file_bundle(src_path, work_dir):
    """Real c2cpg -> export -> the exact same chain run_pipeline_one.py uses, over ONE
    standalone source file, mirroring task #28's own real historical-case methodology (not a
    hand-built fixture)."""
    os.makedirs(work_dir, exist_ok=True)
    cpp_bin = os.path.join(work_dir, "cpp.cpg.bin")
    r = subprocess.run([f"{JOERN_HOME}/c2cpg.sh", "-o", cpp_bin,
                         "--define", "NAPI_DISABLE_CPP_EXCEPTIONS", src_path],
                        capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"c2cpg failed: {r.stdout[-2000:]} {r.stderr[-2000:]}")
    cpp_raw = os.path.join(work_dir, "cpp_raw")
    r = subprocess.run([f"{JOERN_HOME}/joern", "--script",
                         f"{CPP_FRONTEND}/export_c_cpp_facts_v03.sc",
                         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"],
                        capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"export failed: {r.stdout[-2000:]}")
    return cpp_raw


def main():
    # --- 1. vendored-hint heuristic, against real paths task #28 actually observed -----------
    ck("re2 vendored abseil path -> VENDORED_HINT",
       provenance.classify_vendored_hint(
           "vendor/abseil-cpp/absl/base/internal/strerror.cc") == "VENDORED_HINT")
    ck("ffi-napi vendored libffi path -> VENDORED_HINT",
       provenance.classify_vendored_hint("deps/libffi/src/closures.c") == "VENDORED_HINT")
    ck("package-owned path -> PACKAGE_OWNED_HINT",
       provenance.classify_vendored_hint("src/add.cpp") == "PACKAGE_OWNED_HINT")

    # --- 2. tarball_sha256 vs source_tree_sha256 are real, distinct, and the tree hash is ------
    #        independent of the tarball's own bytes -----------------------------------------
    tmp_pkg = "/tmp/_prov_hash_test_pkg"
    shutil.rmtree(tmp_pkg, ignore_errors=True)
    os.makedirs(tmp_pkg)
    with open(os.path.join(tmp_pkg, "a.c"), "w") as f:
        f.write("int a(void) { return 1; }\n")
    m1 = provenance.build_source_manifest(tmp_pkg, b"TARBALL_BYTES_VERSION_ONE", "p", "1.0.0")
    m2 = provenance.build_source_manifest(tmp_pkg, b"COMPLETELY_DIFFERENT_TARBALL_BYTES", "p", "1.0.0")
    ck("tarball_sha256 differs when tarball bytes differ",
       m1["tarball_sha256"] != m2["tarball_sha256"])
    ck("source_tree_sha256 is IDENTICAL when only tarball bytes differ (same real file content)",
       m1["source_tree_sha256"] == m2["source_tree_sha256"])
    ck("tarball_sha256 != source_tree_sha256 (two real, distinct hashes, not aliases)",
       m1["tarball_sha256"] != m1["source_tree_sha256"])
    with open(os.path.join(tmp_pkg, "a.c"), "w") as f:
        f.write("int a(void) { return 2; }\n")  # real content change
    m3 = provenance.build_source_manifest(tmp_pkg, b"TARBALL_BYTES_VERSION_ONE", "p", "1.0.0")
    ck("source_tree_sha256 changes when real file content changes (same tarball bytes as m1)",
       m3["source_tree_sha256"] != m1["source_tree_sha256"])
    shutil.rmtree(tmp_pkg, ignore_errors=True)

    # --- 3. fail-closed actionability ---------------------------------------------------------
    fixture_dir = HERE / "study" / "resource_guard" / "raw_c01_missing_check"
    method_map = provenance.load_method_file_map(str(fixture_dir))
    manifest = provenance.build_source_manifest(str(fixture_dir), b"placeholder", "test-pkg", "1.0.0")
    unresolved = {"method_id": 99999999999}
    provenance.enrich_finding(unresolved, unresolved["method_id"], method_map, manifest,
                               str(fixture_dir), "method_id")
    ck("unresolvable finding: actionable=False (fail-closed)", unresolved["actionable"] is False)
    ck("unresolvable finding: provenance['resolved']=False", unresolved["provenance"]["resolved"] is False)
    ck("unresolvable finding: named reason, not silently dropped",
       unresolved["provenance"]["provenance_hint"] == "FILE_NOT_FOUND_IN_METHODS_TABLE")

    # --- 4. REAL POSITIVE: node-libcurl / Easy::ReadFunction (Resource Guard) -----------------
    npm_corpus = HERE / "npm_corpus"
    sys.path.insert(0, str(npm_corpus))
    import run_pipeline_one as P

    eligible = {}
    with open(npm_corpus / "eligible_packages.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            eligible[(parts[idx["package_name"]], parts[idx["version"]])] = {
                "tarball_url": parts[idx["tarball_url"]]}
    build_config = {}
    with open(npm_corpus / "npm_build_configuration.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            build_config[(parts[idx["package_name"]], parts[idx["version"]])] = \
                parts[idx["exception_configuration"]]

    pkg, version = "node-libcurl", "5.1.2"
    key = (pkg, version)
    if key not in eligible:
        print(f"SKIP node-libcurl diagnostic: {key} not in eligible_packages.tsv")
    else:
        info = eligible[key]
        exc = build_config.get(key)
        work_root = "/tmp/check_provenance_libcurl"
        shutil.rmtree(work_root, ignore_errors=True)
        t0 = time.time()
        rec = P.run_one(pkg, version, info["tarball_url"], exc, work_root)
        print(f"  node-libcurl run: {rec.get('status')} in {time.time()-t0:.1f}s", file=sys.stderr)
        ck("node-libcurl real run reaches ANALYZED", rec.get("status") == "ANALYZED")
        r05_findings = rec.get("r05_findings") or []
        rf = [f for f in r05_findings if "ReadFunction" in (f.get("method_name") or "")]
        ck("node-libcurl reproduces the real Easy::ReadFunction finding", len(rf) >= 1)
        if rf:
            f = rf[0]
            ck("real finding's provenance resolved (actionable=True)", f.get("actionable") is True)
            src_path = f.get("provenance", {}).get("source_path")
            ck("real finding has a non-empty real source_path", bool(src_path))
            real_abs_path = os.path.join(work_root, "pkg", src_path) if src_path else None
            file_existed = real_abs_path and os.path.isfile(real_abs_path)
            ck("real finding's source_path resolves to an actual file on disk"
               " (checked before work_root cleanup)", file_existed)
            if file_existed:
                real_hash = provenance.sha256_hex(open(real_abs_path, "rb").read())
                ck("real finding's content_hash matches independently recomputed hash of the "
                   "real source file", real_hash == f.get("provenance", {}).get("content_hash"))
            ck("real finding retains its own method_id (pre-existing node identity, untouched)",
               "method_id" in f)
        shutil.rmtree(work_root, ignore_errors=True)

    # --- 5/6. REAL POSITIVE: LOCK_BALANCE and PROTECTED_FIELD, freshly built (not stale --------
    #          committed raw facts, whose own filename field predates the fixture_source.cpp
    #          renaming convention and would falsely report PATH_NOT_IN_MANIFEST) -------------
    lockcap = HERE / "study" / "lockcap"
    for name, subdir, script, finding_key, match_reason in (
        ("LOCK_BALANCE", "raw_real_vuln", "lock_balance_verdict.py", "lock_balance_findings",
         "RETURN_REACHABLE_WITHOUT_MATCHING_UNLOCK"),
        ("PROTECTED_FIELD", "raw_xfn_real", "protected_field_verdict.py",
         "protected_field_findings", "MISSING_LOCK_CANDIDATE"),
    ):
        src = lockcap / subdir / "fixture_source.c"
        work_dir = f"/tmp/check_provenance_{name.lower()}"
        shutil.rmtree(work_dir, ignore_errors=True)
        try:
            cpp_raw = build_single_file_bundle(str(src), work_dir)
        except Exception as e:
            ck(f"{name}: fresh real c2cpg build succeeds", False)
            print(f"  {name} build error: {e}", file=sys.stderr)
            continue
        ck(f"{name}: fresh real c2cpg build succeeds", True)

        out_path = os.path.join(work_dir, "out.json")
        r = subprocess.run([sys.executable, str(HERE / script), cpp_raw, out_path],
                            capture_output=True, text=True)
        doc = json.load(open(out_path))
        findings = doc.get("findings", [])
        ck(f"{name}: real fixture produces its own real positive finding", len(findings) >= 1)

        manifest = provenance.build_source_manifest(str(src.parent), b"placeholder_tarball",
                                                       "wolfssl-fixture", "n/a")
        method_map = provenance.load_method_file_map(cpp_raw)
        for f in findings:
            provenance.enrich_finding(f, f.get("method_id"), method_map, manifest,
                                        str(src.parent), "method_id")
        resolved = [f for f in findings if f.get("actionable") is True]
        ck(f"{name}: real finding's provenance resolves (actionable=True) via method_id join,"
           " no scanner-file change needed", len(resolved) >= 1)
        if resolved:
            f = resolved[0]
            ck(f"{name}: resolved source_path is real 'fixture_source.c'",
               f["provenance"]["source_path"] == "fixture_source.c")
            real_hash = provenance.sha256_hex(src.read_bytes())
            ck(f"{name}: content_hash matches independently recomputed real file hash",
               real_hash == f["provenance"]["content_hash"])
            ck(f"{name}: has real distinct tarball_sha256/source_tree_sha256",
               f["provenance"]["tarball_sha256"] != f["provenance"]["source_tree_sha256"])
        shutil.rmtree(work_dir, ignore_errors=True)

    print(f"\nPROVENANCE_CONTROLS={ok}/{total}")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
