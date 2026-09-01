#!/usr/bin/env python3
"""Task #28, phase 1+2: schema-compatibility check + combined six-property pilot.

Reuses run_pipeline_one.py's own download/extract/header-staging/c2cpg/export/normalize
stages verbatim (imported, not reimplemented) so this pilot's evidence bundles are produced
by the EXACT same real pipeline code the npm corpus scan itself used -- not a hand-rolled
approximation. Unlike run_pipeline_one.py, this script does NOT delete cpp_raw/cpp_facts.json
(and its .operandrole.json/.destcapacity.json/.srccapacity.json/.cmpcapacity.json/.bound.json
sidecars, produced by normalize_c_cpp_facts_v03.py as a side effect it already emits) after
each package -- those ARE this pilot's real evidence bundles, kept under /tmp for inspection
(not committed: real per-package Joern fact tables are large binary/TSV data, consistent with
the existing pipeline's own disk-bounding discipline, which this pilot otherwise preserves).

For each package, runs all SIX properties' scanners against the SAME real evidence bundle:
  - FALLIBLE_BOUNDED_RESOURCE (already executed by the stopped pipeline; run here again only
    so this pilot's six-property record is directly comparable) via resource_guard_verdict_r04.py
    + resource_guard_verdict_r05.py, reading cpp_raw/ directly (unchanged from the existing
    pipeline).
  - LOCK_BALANCE via lock_balance_verdict.py, reading cpp_raw/ directly.
  - PROTECTED_FIELD via protected_field_verdict.py, reading cpp_raw/ directly.
  - OOB_WRITE / OOB_READ / OOB_COMPARE via oob_write_verdict.py / oob_read_verdict.py /
    oob_compare_verdict.py, each consuming cpp_facts.json + its own sidecar files (imported
    in-process, not subprocessed, since these scripts expose emit_candidates() directly and
    print rather than write JSON on their own).

Records, per scanner per package, independently keyed (never overwriting or colliding with the
existing r04_/r05_ keys the stopped pipeline already uses): real wall-clock seconds, a
schema_compatibility verdict (COMPATIBLE / INCOMPATIBLE with the real exception text if one was
raised), and the real classification/candidate counts (positive, negative/safe, and abstention
buckets as each scanner's OWN vocabulary defines them -- not force-fit into one shared taxonomy).

Run: python3 run_pilot.py <schema_check|multi_pilot> <out.jsonl>
  schema_check: one package (@fqlan/add-example-prebuild -- the same package the ORIGINAL
                run_pipeline_one.py was itself manually validated against before being written,
                per that file's own module docstring).
  multi_pilot:  five small real packages (n_cpp_files=1 each, from eligible_packages.tsv),
                before any corpus-scale rerun.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time

REPO = "/tmp/integration_pilot_wt"
SCANNER_V2 = f"{REPO}/semantic-bucket-pilot/scanner-v2"
NPM_CORPUS = f"{SCANNER_V2}/npm_corpus"
OOB_TOOLS = f"{REPO}/tchecker-research-complete/portable-engine-full-review-package/tools"

sys.path.insert(0, NPM_CORPUS)
import run_pipeline_one as P  # noqa: E402  -- reuse the real pipeline's own stage functions

SCHEMA_CHECK_PKGS = ["@fqlan/add-example-prebuild"]
MULTI_PILOT_PKGS = ["@fqlan/add-example-prebuild", "@camol/file-lock", "@archwayhq/keyring-go",
                     "@deepfocus/get-windows", "@co_snow/hello"]


def load_eligible_and_build_config():
    eligible = {}
    with open(f"{NPM_CORPUS}/eligible_packages.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            eligible[parts[idx["package_name"]]] = {
                "version": parts[idx["version"]], "tarball_url": parts[idx["tarball_url"]]}
    build_config = {}
    with open(f"{NPM_CORPUS}/npm_build_configuration.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            build_config[(parts[idx["package_name"]], parts[idx["version"]])] = \
                parts[idx["exception_configuration"]]
    return eligible, build_config


def import_oob_module(name):
    spec = importlib.util.spec_from_file_location(name, f"{OOB_TOOLS}/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_scanner_subprocess(cmd, timeout=180):
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - t0
        return proc.returncode, proc.stdout, proc.stderr, elapsed, None
    except subprocess.TimeoutExpired:
        return None, "", "", time.time() - t0, "TIMEOUT"
    except Exception as e:
        return None, "", "", time.time() - t0, f"{type(e).__name__}: {e}"


def build_evidence_bundle(pkg_name, version, tarball_url, exception_config, work_root):
    """Runs the real pipeline stages through cpp_export + cpp_normalize (reusing
    run_pipeline_one.py's own functions verbatim), WITHOUT deleting the results. Returns
    (record, cpp_raw_dir, cpp_facts_path, build_config_path) or (record, None, None, None)
    on failure -- record carries the same stage timing/status shape run_pipeline_one.py itself
    produces, so a failure here is directly comparable to a failure in the stopped corpus scan."""
    record = {"package_name": pkg_name, "version": version, "stages": {}, "status": None,
              "detail": ""}
    pkg_dir = os.path.join(work_root, "pkg")
    work = os.path.join(work_root, "work")
    for d in (pkg_dir, work):
        os.makedirs(d, exist_ok=True)

    t0 = time.time()
    tb, err = P.fetch_bytes(tarball_url)
    record["stages"]["download"] = {"seconds": time.time() - t0}
    if err:
        record["status"] = "DOWNLOAD_FAILED"
        record["detail"] = err
        return record, None, None, None

    t0 = time.time()
    try:
        import tarfile, io
        tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r:gz")
        tf.extractall(pkg_dir, filter="data")
        tf.close()
        inner = os.path.join(pkg_dir, "package")
        if os.path.isdir(inner):
            for name in os.listdir(inner):
                shutil.move(os.path.join(inner, name), os.path.join(pkg_dir, name))
            os.rmdir(inner)
    except Exception as e:
        record["status"] = "EXTRACTION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record, None, None, None
    record["stages"]["extract"] = {"seconds": time.time() - t0}

    t0 = time.time()
    include_dirs, header_evidence = P.stage_native_dep_headers(pkg_dir, work_root)
    record["header_staging"] = header_evidence
    record["stages"]["header_staging"] = {"seconds": time.time() - t0, "n_staged": len(include_dirs)}

    cpp_bin = os.path.join(work, "cpp.cpg.bin")
    c2cpg_cmd = [f"{P.JOERN_HOME}/c2cpg.sh", "-o", cpp_bin]
    for d in include_dirs:
        c2cpg_cmd += ["--include", d]
    c2cpg_cmd += ["--define", "NAPI_CPP_EXCEPTIONS" if exception_config == "enabled"
                  else "NAPI_DISABLE_CPP_EXCEPTIONS"]
    c2cpg_cmd.append(pkg_dir)
    rc, secs, mem, err = P.run_stage(c2cpg_cmd, os.path.join(work, "cpp_gen.log"))
    record["stages"]["c2cpg"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "CPP_CPG_FAILED"
        record["detail"] = err or f"c2cpg rc={rc}"
        return record, None, None, None

    cpp_raw = os.path.join(work, "cpp_raw")
    rc, secs, mem, err = P.run_stage(
        [f"{P.JOERN_HOME}/joern", "--script", f"{P.CPP_FRONTEND}/export_c_cpp_facts_v03.sc",
         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"],
        os.path.join(work, "cpp_export.log"))
    record["stages"]["cpp_export"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"cpp export rc={rc}"
        return record, None, None, None

    cpp_facts = os.path.join(work, "cpp_facts.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{P.CPP_FRONTEND}/normalize_c_cpp_facts_v03.py",
                         cpp_raw, cpp_facts], check=True, timeout=P.NORMALIZE_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except Exception as e:
        record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record, None, None, None
    record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}

    build_config_path = os.path.join(work, "build_config.json")
    with open(build_config_path, "w") as f:
        json.dump({"exception_configuration": exception_config or "unresolved",
                    "evidence": [], "citation": "from npm_build_configuration.tsv"}, f)

    record["status"] = "BUNDLE_READY"
    return record, cpp_raw, cpp_facts, build_config_path


def run_six_properties(pkg_name, cpp_raw, cpp_facts, build_config_path):
    """Runs all six properties' scanners against ONE real evidence bundle. Returns a dict
    with independently-keyed classification/findings/candidates, timings, and a
    schema_compatibility verdict per scanner."""
    out = {"timings": {}, "schema_compatibility": {}}

    # --- FALLIBLE_BOUNDED_RESOURCE (R04 + R05) -- unchanged from the stopped pipeline ------
    for rev in ("r04", "r05"):
        out_path = f"/tmp/_pilot_{pkg_name.replace('/', '_')}_{rev}.json"
        cmd = [sys.executable, f"{SCANNER_V2}/resource_guard_verdict_{rev}.py",
               cpp_raw, out_path, "--real", "--build-config", build_config_path]
        rc, sout, serr, secs, err = run_scanner_subprocess(cmd)
        out["timings"][rev] = secs
        if err or rc != 0:
            out["schema_compatibility"][rev] = f"INCOMPATIBLE: {err or serr.strip()[-500:]}"
            out[f"{rev}_classification"] = None
            out[f"{rev}_findings"] = None
            continue
        with open(out_path) as f:
            doc = json.load(f)
        out["schema_compatibility"][rev] = "COMPATIBLE"
        out[f"{rev}_classification"] = doc.get("classification", {})
        out[f"{rev}_findings"] = doc.get("findings", [])

    # --- LOCK_BALANCE / PROTECTED_FIELD -- both read cpp_raw/ directly, same shape as R04/R05
    for name, script in (("lock_balance", "lock_balance_verdict.py"),
                          ("protected_field", "protected_field_verdict.py")):
        out_path = f"/tmp/_pilot_{pkg_name.replace('/', '_')}_{name}.json"
        cmd = [sys.executable, f"{SCANNER_V2}/{script}", cpp_raw, out_path]
        rc, sout, serr, secs, err = run_scanner_subprocess(cmd)
        out["timings"][name] = secs
        if err or rc != 0:
            out["schema_compatibility"][name] = f"INCOMPATIBLE: {err or serr.strip()[-500:]}"
            out[f"{name}_classification"] = None
            out[f"{name}_findings"] = None
            continue
        with open(out_path) as f:
            doc = json.load(f)
        out["schema_compatibility"][name] = "COMPATIBLE"
        out[f"{name}_classification"] = doc.get("classification", {})
        out[f"{name}_findings"] = doc.get("findings", [])

    # --- OOB_WRITE / OOB_READ / OOB_COMPARE -- consume cpp_facts.json + normalizer sidecars,
    # imported in-process since these modules expose emit_candidates() directly.
    for name, modname in (("oob_write", "oob_write_verdict"), ("oob_read", "oob_read_verdict"),
                           ("oob_compare", "oob_compare_verdict")):
        t0 = time.time()
        try:
            mod = import_oob_module(modname)
            candidates = mod.emit_candidates(cpp_facts)
            secs = time.time() - t0
            out["timings"][name] = secs
            out["schema_compatibility"][name] = "COMPATIBLE"
            out[f"{name}_candidates"] = candidates
        except FileNotFoundError as e:
            secs = time.time() - t0
            out["timings"][name] = secs
            out["schema_compatibility"][name] = f"INCOMPATIBLE: missing sidecar file: {e}"
            out[f"{name}_candidates"] = None
        except Exception as e:
            secs = time.time() - t0
            out["timings"][name] = secs
            out["schema_compatibility"][name] = f"INCOMPATIBLE: {type(e).__name__}: {e}"
            out[f"{name}_candidates"] = None

    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "schema_check"
    out_path = sys.argv[2] if len(sys.argv) > 2 else f"{mode}_results.jsonl"
    pkgs = SCHEMA_CHECK_PKGS if mode == "schema_check" else MULTI_PILOT_PKGS

    eligible, build_config = load_eligible_and_build_config()

    with open(out_path, "w") as outf:
        for pkg_name in pkgs:
            info = eligible.get(pkg_name)
            if not info:
                print(f"SKIP {pkg_name}: not in eligible_packages.tsv", file=sys.stderr)
                continue
            version = info["version"]
            exc_config = build_config.get((pkg_name, version))
            work_root = f"/tmp/integration_pilot_bundles/{pkg_name.replace('/', '_')}"
            shutil.rmtree(work_root, ignore_errors=True)
            os.makedirs(work_root, exist_ok=True)

            print(f"=== {pkg_name}@{version} ===", file=sys.stderr)
            t0 = time.time()
            bundle_record, cpp_raw, cpp_facts, build_config_path = build_evidence_bundle(
                pkg_name, version, info["tarball_url"], exc_config, work_root)
            bundle_record["bundle_seconds"] = time.time() - t0

            result = {"package_name": pkg_name, "version": version, "bundle": bundle_record}
            if bundle_record["status"] != "BUNDLE_READY":
                print(f"  BUNDLE FAILED: {bundle_record['status']} -- {bundle_record['detail']}",
                      file=sys.stderr)
                outf.write(json.dumps(result) + "\n")
                outf.flush()
                continue

            t0 = time.time()
            six_props = run_six_properties(pkg_name, cpp_raw, cpp_facts, build_config_path)
            six_props["total_scanner_seconds"] = time.time() - t0
            result["six_properties"] = six_props

            for k, v in six_props["schema_compatibility"].items():
                print(f"  {k}: {v if not v.startswith('COMPATIBLE') else 'COMPATIBLE'} "
                      f"({six_props['timings'][k]:.2f}s)", file=sys.stderr)

            outf.write(json.dumps(result) + "\n")
            outf.flush()

    print(f"\nWrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
