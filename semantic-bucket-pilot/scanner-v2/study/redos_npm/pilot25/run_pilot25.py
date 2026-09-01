#!/usr/bin/env python3
"""REDOS-PILOT25-R01, step 6: runs the frozen ReDoS pipeline (jssrc2cpg -> export_redos_npm_
integ.sc -> redos_verdict.py) ONCE over exactly the 21 packages frozen in pilot25_selection.json
-- selected and committed before this script ever ran, per direct instruction ("don't modify the
analyzer after selecting a blind package"). Neither export_redos_npm_integ.sc nor redos_verdict.py
is touched by this script.

Writes pilot25_results.json: per-package sink/DANGEROUS/export counts and the full reduced
findings list (still reportable=false, unchanged from redos_verdict.py's own contract).
"""
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
SELECTION_PATH = os.path.join(HERE, "pilot25_selection.json")
RESULTS_PATH = os.path.join(HERE, "pilot25_results.json")

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/"
            "producers/export_redos_npm_integ.sc")
VERDICT = os.path.join(SCANNER_V2, "redos_verdict.py")

FETCH_TIMEOUT = 60
JSSRC2CPG_TIMEOUT = 300
JOERN_TIMEOUT = 300


def fetch_tarball(url):
    req = urllib.request.Request(url, headers={"User-Agent": "redos-pilot25/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read()


def run_one(pkg):
    name, ver, url = pkg["package_name"], pkg["version"], pkg["tarball_url"]
    out = {"package_name": name, "version": ver, "row_index": pkg["row_index"],
           "supported_sink_count_prefilter": pkg["supported_sink_count"]}
    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        src_dir = os.path.join(td, "src")
        os.makedirs(src_dir, exist_ok=True)
        try:
            data = fetch_tarball(url)
        except Exception as e:
            out["status"] = "FETCH_FAILED"
            out["error"] = str(e)
            return out
        try:
            with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:gz") as tf:
                tf.extractall(src_dir)
        except Exception as e:
            out["status"] = "EXTRACT_FAILED"
            out["error"] = str(e)
            return out

        cpg_path = os.path.join(td, "x.cpg.bin")
        r1 = subprocess.run([f"{JOERN_HOME}/jssrc2cpg.sh", "-o", cpg_path, src_dir],
                             capture_output=True, text=True, timeout=JSSRC2CPG_TIMEOUT)
        if not os.path.isfile(cpg_path):
            out["status"] = "CPG_BUILD_FAILED"
            out["error"] = (r1.stdout + r1.stderr)[-2000:]
            return out

        raw_dir = os.path.join(td, "raw")
        r2 = subprocess.run([f"{JOERN_HOME}/joern", "--script", PRODUCER,
                              "--param", f"cpgFile={cpg_path}",
                              "--param", f"rawDir={raw_dir}",
                              "--param", f"srcLabel={name}"],
                             capture_output=True, text=True, timeout=JOERN_TIMEOUT)
        producer_log = r2.stdout + r2.stderr
        summary_path = os.path.join(raw_dir, "redos_npm_summary.json")
        if os.path.isfile(summary_path):
            out["producer_summary"] = json.load(open(summary_path))
        else:
            out["status"] = "PRODUCER_FAILED"
            out["error"] = producer_log[-2000:]
            return out

        verdict_out = os.path.join(td, "verdict.json")
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
    out["elapsed_seconds"] = round(time.time() - t0, 1)
    return out


def main():
    sel = json.load(open(SELECTION_PATH))
    pkgs = sel["selected"]
    print(f"running frozen ReDoS pipeline over {len(pkgs)} pre-registered packages", file=sys.stderr)
    results = []
    if os.path.exists(RESULTS_PATH):
        os.remove(RESULTS_PATH)
    for i, pkg in enumerate(pkgs):
        print(f"[{i+1}/{len(pkgs)}] {pkg['package_name']}@{pkg['version']}...", file=sys.stderr)
        r = run_one(pkg)
        results.append(r)
        n_findings = len(r.get("findings") or [])
        print(f"  -> status={r.get('status')} findings={n_findings} "
              f"elapsed={r.get('elapsed_seconds')}s", file=sys.stderr)
        with open(RESULTS_PATH, "w") as f:
            json.dump({"selection_schema": sel["schema"], "n_packages": len(pkgs),
                       "results": results}, f, indent=2)
    n_ok = sum(1 for r in results if r.get("status") == "OK")
    n_with_findings = sum(1 for r in results if r.get("findings"))
    total_findings = sum(len(r.get("findings") or []) for r in results)
    print(f"DONE: {n_ok}/{len(pkgs)} OK, {n_with_findings} packages with >=1 finding, "
          f"{total_findings} total findings", file=sys.stderr)


if __name__ == "__main__":
    main()
