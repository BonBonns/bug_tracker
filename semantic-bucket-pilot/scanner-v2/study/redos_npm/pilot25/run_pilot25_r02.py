#!/usr/bin/env python3
"""ReDoS R02 regression run: reruns ALL 21 original pilot25 packages -- "use these 21 packages
strictly as the development/regression set" -- through the FULL corrected pipeline: frontend
entrypoint-coverage correction (audit/frontend_coverage_check.py) -> the new R02 producer
(export_redos_npm_integ_r02.sc) -> the frozen, unmodified reducer (redos_verdict.py). Compares
every package's result against pilot25_results.json's own already-recorded real baseline.

This is the real, complete regression check before R02 + the frontend rule can honestly be
called "frozen" -- the 4-package spot check in R02_IMPLEMENTATION.md and the 2-package spot
check in FRONTEND_COVERAGE_FIX.md covered only 5 of the 21; this covers all 21, mechanically,
reusing (never modifying) both already-committed, already-validated tools.

Neither export_redos_npm_integ.sc (R01), export_redos_npm_integ_r02.sc, redos_verdict.py, nor
frontend_coverage_check.py is modified by this script -- it only imports and orchestrates them,
exactly as run_pilot25.py already orchestrates the R01-only pipeline.
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
AUDIT_DIR = os.path.join(HERE, "audit")
sys.path.insert(0, AUDIT_DIR)
import frontend_coverage_check as fcc  # noqa: E402 -- reused, never modified

SELECTION_PATH = os.path.join(HERE, "pilot25_selection.json")
BASELINE_PATH = os.path.join(HERE, "pilot25_results.json")
RESULTS_PATH = os.path.join(HERE, "pilot25_r02_results.json")

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
R02_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/"
                "producers/export_redos_npm_integ_r02.sc")
VERDICT = os.path.join(SCANNER_V2, "redos_verdict.py")

FETCH_TIMEOUT = 60
JOERN_TIMEOUT = 300


def fetch_and_extract(tarball_url, dest_root):
    req = urllib.request.Request(tarball_url, headers={"User-Agent": "redos-pilot25-r02/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        data = resp.read()
    src_dir = os.path.join(dest_root, "src")
    os.makedirs(src_dir, exist_ok=True)
    with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:gz") as tf:
        tf.extractall(src_dir)
    return src_dir


def run_r02_producer(cpg_path, raw_dir, src_label):
    r = subprocess.run([f"{JOERN_HOME}/joern", "--script", R02_PRODUCER,
                         "--param", f"cpgFile={cpg_path}",
                         "--param", f"rawDir={raw_dir}",
                         "--param", f"srcLabel={src_label}"],
                        capture_output=True, text=True, timeout=JOERN_TIMEOUT)
    log = r.stdout + r.stderr
    summary_path = os.path.join(raw_dir, "redos_npm_summary.json")
    if os.path.isfile(summary_path):
        return json.load(open(summary_path)), log
    return None, log


def run_one(pkg):
    name, ver, url = pkg["package_name"], pkg["version"], pkg["tarball_url"]
    out = {"package_name": name, "version": ver, "row_index": pkg["row_index"]}
    t0 = time.time()
    work_dir = tempfile.mkdtemp(prefix="pilot25_r02_")
    try:
        try:
            src_dir = fetch_and_extract(url, work_dir)
        except Exception as e:
            out["status"] = "FETCH_FAILED"
            out["error"] = str(e)
            return out

        # ----- frontend entrypoint-coverage: build CPG, correct if a resolved entrypoint is
        # missing because of a jssrc2cpg default-ignore rule (fcc.check_package's own real logic,
        # reused verbatim -- never a separate reimplementation of its correction discipline).
        try:
            pkg_json_path = fcc.find_package_json(src_dir)
            if pkg_json_path is None:
                out["status"] = "NO_PACKAGE_JSON"
                return out
            with open(pkg_json_path) as f:
                pkg_doc = json.load(f)
            entrypoints = fcc.resolve_entrypoints(pkg_doc)
            pkg_root = os.path.dirname(pkg_json_path)
            pkg_root_rel = os.path.relpath(pkg_root, src_dir).replace(os.sep, "/")
            if pkg_root_rel == ".":
                pkg_root_rel = ""

            def to_src_dir_rel(ep):
                return (pkg_root_rel + "/" + ep) if pkg_root_rel else ep

            cpg1 = os.path.join(work_dir, "pass1.cpg.bin")
            ok1, log1 = fcc.build_cpg(src_dir, cpg1)
            if not ok1:
                out["status"] = "CPG_BUILD_FAILED"
                out["error"] = log1[-2000:]
                return out
            cpg1_files, _ = fcc.list_cpg_files(cpg1)
            cpg1_files_set = set(cpg1_files)

            missing = []
            for ep in entrypoints:
                relpath = to_src_dir_rel(ep)
                if relpath in cpg1_files_set:
                    continue
                abspath = os.path.join(src_dir, *relpath.split("/"))
                if not os.path.isfile(abspath):
                    continue
                reason = fcc.classify_ignore_reason(relpath, abspath)
                if reason:
                    missing.append((relpath, reason))

            out["frontend_coverage"] = {
                "resolved_entrypoints": entrypoints,
                "n_missing_entrypoints": len(missing),
                "missing_entrypoints": [{"relpath": r, "reason": rs} for r, rs in missing],
            }

            final_cpg = cpg1
            if missing:
                staged_dir, recovered_map = fcc.stage_recovered_source(src_dir, missing)
                cpg2 = os.path.join(work_dir, "pass2.cpg.bin")
                ok2, log2 = fcc.build_cpg(staged_dir, cpg2)
                if ok2:
                    cpg2_files, _ = fcc.list_cpg_files(cpg2)
                    cpg2_files_set = set(cpg2_files)
                    still_missing = [(r, rs) for r, rs in missing
                                      if recovered_map.get(r) not in cpg2_files_set]
                    out["frontend_coverage"]["correction_applied"] = True
                    out["frontend_coverage"]["recovered_path_map"] = recovered_map
                    out["frontend_coverage"]["still_missing_after_correction"] = still_missing
                    final_cpg = cpg2
                else:
                    out["frontend_coverage"]["correction_applied"] = False
                    out["frontend_coverage"]["correction_error"] = log2[-1000:]
            else:
                out["frontend_coverage"]["correction_applied"] = False
        except Exception as e:
            out["status"] = "FRONTEND_COVERAGE_FAILED"
            out["error"] = repr(e)
            return out

        # ----- R02 producer -----
        raw_dir = os.path.join(work_dir, "raw")
        summary, plog = run_r02_producer(final_cpg, raw_dir, name)
        if summary is None:
            out["status"] = "PRODUCER_FAILED"
            out["error"] = plog[-2000:]
            return out
        out["producer_summary"] = summary

        # ----- reducer (frozen, unmodified) -----
        verdict_out = os.path.join(work_dir, "verdict.json")
        r3 = subprocess.run([sys.executable, VERDICT, raw_dir, src_dir, verdict_out],
                             capture_output=True, text=True, timeout=120)
        if not os.path.isfile(verdict_out):
            out["status"] = "REDUCER_FAILED"
            out["error"] = (r3.stdout + r3.stderr)[-2000:]
            return out
        vdoc = json.load(open(verdict_out))
        out["status"] = "OK"
        out["classification"] = vdoc["classification"]
        out["findings"] = vdoc["findings"]
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    out["elapsed_seconds"] = round(time.time() - t0, 1)
    return out


def compare_to_baseline(baseline_by_name, r02_result):
    name = r02_result["package_name"]
    base = baseline_by_name.get(name)
    if base is None:
        return {"comparable": False, "note": "no baseline record"}
    b_summary = base.get("producer_summary") or {}
    r_summary = r02_result.get("producer_summary") or {}
    b_findings = base.get("findings") or []
    r_findings = r02_result.get("findings") or []
    return {
        "comparable": True,
        "baseline_status": base.get("status"), "r02_status": r02_result.get("status"),
        "baseline_dangerous_sinks": b_summary.get("dangerous_sinks"),
        "r02_dangerous_sinks": r_summary.get("dangerous_sinks"),
        "baseline_n_findings": len(b_findings), "r02_n_findings": len(r_findings),
        "baseline_pkg_api_reachable": (base.get("classification") or {}).get("PACKAGE_API_INPUT_REACHABLE"),
        "r02_pkg_api_reachable": (r02_result.get("classification") or {}).get("PACKAGE_API_INPUT_REACHABLE"),
        "regression_flag": (len(b_findings) > 0 and len(r_findings) < len(b_findings)),
    }


def main():
    sel = json.load(open(SELECTION_PATH))
    pkgs = sel["selected"]
    baseline = json.load(open(BASELINE_PATH))
    baseline_by_name = {r["package_name"]: r for r in baseline["results"]}

    print(f"running R02 pipeline (frontend-coverage-corrected + R02 producer) over "
          f"{len(pkgs)} pre-registered development/regression packages", file=sys.stderr)
    results = []
    if os.path.exists(RESULTS_PATH):
        os.remove(RESULTS_PATH)
    for i, pkg in enumerate(pkgs):
        print(f"[{i+1}/{len(pkgs)}] {pkg['package_name']}@{pkg['version']}...", file=sys.stderr)
        r = run_one(pkg)
        r["comparison_to_r01_baseline"] = compare_to_baseline(baseline_by_name, r)
        results.append(r)
        c = r["comparison_to_r01_baseline"]
        print(f"  -> status={r.get('status')} "
              f"dangerous_sinks base={c.get('baseline_dangerous_sinks')}->r02={c.get('r02_dangerous_sinks')} "
              f"findings base={c.get('baseline_n_findings')}->r02={c.get('r02_n_findings')} "
              f"REGRESSION={c.get('regression_flag')} "
              f"elapsed={r.get('elapsed_seconds')}s", file=sys.stderr)
        with open(RESULTS_PATH, "w") as f:
            json.dump({"selection_schema": sel["schema"], "n_packages": len(pkgs),
                       "results": results}, f, indent=2)

    n_ok = sum(1 for r in results if r.get("status") == "OK")
    n_regressions = sum(1 for r in results if r["comparison_to_r01_baseline"].get("regression_flag"))
    n_new_findings = sum(1 for r in results
                          if len(r.get("findings") or []) > r["comparison_to_r01_baseline"].get("baseline_n_findings", 0))
    print(f"DONE: {n_ok}/{len(pkgs)} OK, {n_regressions} REGRESSIONS (must be 0), "
          f"{n_new_findings} packages with MORE findings than the R01 baseline", file=sys.stderr)


if __name__ == "__main__":
    main()
