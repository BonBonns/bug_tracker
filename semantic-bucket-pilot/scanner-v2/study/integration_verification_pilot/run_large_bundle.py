#!/usr/bin/env python3
"""Task #28 next-phase, step 5: one large real evidence bundle (re2 -- 551 real C/C++ files,
the same package `CORPUS_STATUS.md`'s own 50-package pilot already documented as a real,
disclosed high-resource case: c2cpg up to 41.4s, cpp_export/normalize up to 127.6s -- chosen
FOR that existing real precedent, not cherry-picked after seeing this pilot's own results).
Records real wall-clock time AND real peak-RSS delta (resource.getrusage(RUSAGE_CHILDREN),
same technique run_pipeline_one.py's own rss_now() uses) for every one of the 6 properties'
scanner invocations, plus the bundle-build stages themselves.

Run: python3 run_large_bundle.py <out.json>
"""
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/integration_pilot_wt/semantic-bucket-pilot/scanner-v2/npm_corpus")
import run_pipeline_one as P  # noqa: E402

SCANNER_V2 = "/tmp/integration_pilot_wt/semantic-bucket-pilot/scanner-v2"
HERE = os.path.dirname(os.path.abspath(__file__))

PKG_NAME = "re2"
PKG_VERSION = "1.26.1"
TARBALL_URL = "https://registry.npmjs.org/re2/-/re2-1.26.1.tgz"
EXCEPTION_CONFIG = None  # real npm_build_configuration.tsv value: "unresolved"


def build_bundle(work_root):
    record, cpp_raw, cpp_facts, build_config_path = None, None, None, None
    pkg_dir = os.path.join(work_root, "pkg")
    work = os.path.join(work_root, "work")
    for d in (pkg_dir, work):
        os.makedirs(d, exist_ok=True)

    stages = {}
    t0 = time.time()
    tb, err = P.fetch_bytes(TARBALL_URL)
    stages["download"] = {"seconds": time.time() - t0}
    if err:
        return {"status": "DOWNLOAD_FAILED", "detail": err, "stages": stages}, None, None, None

    t0 = time.time()
    import tarfile, io
    tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r:gz")
    tf.extractall(pkg_dir, filter="data")
    tf.close()
    inner = os.path.join(pkg_dir, "package")
    if os.path.isdir(inner):
        for name in os.listdir(inner):
            shutil.move(os.path.join(inner, name), os.path.join(pkg_dir, name))
        os.rmdir(inner)
    stages["extract"] = {"seconds": time.time() - t0}

    t0 = time.time()
    include_dirs, header_evidence = P.stage_native_dep_headers(pkg_dir, work_root)
    stages["header_staging"] = {"seconds": time.time() - t0, "n_staged": len(include_dirs)}

    cpp_bin = os.path.join(work, "cpp.cpg.bin")
    c2cpg_cmd = [f"{P.JOERN_HOME}/c2cpg.sh", "-o", cpp_bin]
    for d in include_dirs:
        c2cpg_cmd += ["--include", d]
    c2cpg_cmd += ["--define", "NAPI_DISABLE_CPP_EXCEPTIONS", pkg_dir]
    # re2 is the documented real high-resource case (CORPUS_STATUS.md: c2cpg 41.4s max,
    # normalize 127.6s max on a prior real run) -- give real margin via the SAME
    # TIMEOUT_MULTIPLIER mechanism the frozen pipeline itself uses for its own retry queue,
    # rather than a made-up number.
    big_timeout = 8 * 180
    rc, secs, mem, err = P.run_stage(c2cpg_cmd, os.path.join(work, "cpp_gen.log"), timeout=big_timeout)
    stages["c2cpg"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        return {"status": "RESOURCE_LIMIT" if err == "TIMEOUT" else "CPP_CPG_FAILED",
                "detail": err or f"rc={rc}", "stages": stages}, None, None, None

    cpp_raw = os.path.join(work, "cpp_raw")
    rc, secs, mem, err = P.run_stage(
        [f"{P.JOERN_HOME}/joern", "--script", f"{P.CPP_FRONTEND}/export_c_cpp_facts_v03.sc",
         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"],
        os.path.join(work, "cpp_export.log"), timeout=big_timeout)
    stages["cpp_export"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        return {"status": "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED",
                "detail": err or f"rc={rc}", "stages": stages}, None, None, None

    cpp_facts = os.path.join(work, "cpp_facts.json")
    before = P.rss_now()
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{P.CPP_FRONTEND}/normalize_c_cpp_facts_v03.py",
                         cpp_raw, cpp_facts], check=True, timeout=big_timeout,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except Exception as e:
        stages["cpp_normalize"] = {"seconds": time.time() - t0}
        return {"status": "NORMALIZATION_FAILED", "detail": f"{type(e).__name__}: {e}",
                "stages": stages}, None, None, None
    stages["cpp_normalize"] = {"seconds": time.time() - t0,
                                "maxrss_delta_kb": max(0, P.rss_now() - before)}

    build_config_path = os.path.join(work, "build_config.json")
    with open(build_config_path, "w") as f:
        json.dump({"exception_configuration": EXCEPTION_CONFIG or "unresolved",
                    "evidence": [], "citation": "from npm_build_configuration.tsv"}, f)

    n_calls_tsv = sum(1 for _ in open(os.path.join(cpp_raw, "calls.tsv"))) if \
        os.path.exists(os.path.join(cpp_raw, "calls.tsv")) else 0
    return {"status": "BUNDLE_READY", "stages": stages,
            "real_scale": {"n_calls_tsv_rows": n_calls_tsv}}, cpp_raw, cpp_facts, build_config_path


def run_scanner(cmd, timeout=8 * 180):
    return P.run_stage(cmd, "/tmp/_large_bundle_scanner.log", timeout=timeout)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "large_bundle_results.json"
    work_root = "/tmp/large_bundle_re2"
    shutil.rmtree(work_root, ignore_errors=True)
    os.makedirs(work_root, exist_ok=True)

    print(f"=== {PKG_NAME}@{PKG_VERSION} (large evidence bundle) ===", file=sys.stderr)
    t0 = time.time()
    bundle, cpp_raw, cpp_facts, build_config_path = build_bundle(work_root)
    bundle["bundle_seconds"] = time.time() - t0
    result = {"package_name": PKG_NAME, "version": PKG_VERSION, "bundle": bundle}
    print(f"bundle status: {bundle['status']} ({bundle['bundle_seconds']:.1f}s)", file=sys.stderr)
    for k, v in bundle["stages"].items():
        print(f"  {k}: {v}", file=sys.stderr)

    if bundle["status"] != "BUNDLE_READY":
        json.dump(result, open(out_path, "w"), indent=1)
        return

    scanners = {}
    for rev in ("r04", "r05"):
        out = f"/tmp/_large_{rev}.json"
        rc, secs, mem, err = run_scanner(
            [sys.executable, f"{SCANNER_V2}/resource_guard_verdict_{rev}.py",
             cpp_raw, out, "--real", "--build-config", build_config_path])
        scanners[rev] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc, "error": err}
        if not err and rc == 0:
            doc = json.load(open(out))
            scanners[rev]["classification"] = doc.get("classification", {})
            scanners[rev]["n_findings"] = len(doc.get("findings", []))

    for name, script in (("lock_balance", "lock_balance_verdict.py"),
                          ("protected_field", "protected_field_verdict.py")):
        out = f"/tmp/_large_{name}.json"
        rc, secs, mem, err = run_scanner([sys.executable, f"{SCANNER_V2}/{script}", cpp_raw, out])
        scanners[name] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc, "error": err}
        if not err and rc == 0:
            doc = json.load(open(out))
            scanners[name]["classification"] = doc.get("classification", {})
            scanners[name]["n_findings"] = len(doc.get("findings", []))

    for name, modname in (("oob_write", "oob_write_verdict"), ("oob_read", "oob_read_verdict"),
                           ("oob_compare", "oob_compare_verdict")):
        out = f"/tmp/_large_{name}.json"
        rc, secs, mem, err = run_scanner(
            [sys.executable, f"{HERE}/oob_runner.py", modname, cpp_facts, out])
        scanners[name] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc, "error": err}
        if not err and rc == 0:
            doc = json.load(open(out))
            scanners[name]["n_candidates"] = len(doc.get("candidates", []))

    result["scanners"] = scanners
    print(json.dumps(scanners, indent=1, default=str), file=sys.stderr)
    json.dump(result, open(out_path, "w"), indent=1, default=str)
    print(f"\nWrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
