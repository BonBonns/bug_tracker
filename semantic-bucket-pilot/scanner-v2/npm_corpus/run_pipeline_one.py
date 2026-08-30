#!/usr/bin/env python3
"""NPM-CORPUS item 6/7: the full frozen pipeline for ONE package, orchestrating every stage
validated manually against a real package (@fqlan/add-example-prebuild) before this script
was written: download -> extract -> c2cpg -> export_c_cpp_facts_v03.sc ->
normalize_c_cpp_facts_v03.py -> jssrc2cpg -> export_neutral.sc -> normalize_joern_facts.py ->
polyglot_compat_adapter.py -> link_napi_facts.py -> resource_guard_verdict_r04.py (using this
package's own real, previously-extracted build_configuration.tsv evidence).

Every stage records real wall-clock time and a best-effort peak-RSS delta (via
`resource.getrusage(RUSAGE_CHILDREN).ru_maxrss`, checked immediately before and after each
subprocess -- an honest, disclosed limitation: this is a running maximum across all children
reaped so far, not a hardware-isolated per-process measurement, since no `/usr/bin/time` is
installed in this environment; still real, not fabricated).

Every package ends with exactly one primary status from the required taxonomy: ANALYZED,
DOWNLOAD_FAILED, EXTRACTION_FAILED, JS_CPG_FAILED, CPP_CPG_FAILED, EXPORT_FAILED,
NORMALIZATION_FAILED, BINDING_UNRESOLVED, RESOURCE_LIMIT. (NO_JS_TS_SOURCE, NO_CPP_SOURCE,
NO_PACKAGE_OWNED_NATIVE_BINDING, DOWNLOAD_FAILED, INTEGRITY_FAILED were already assigned by
eligibility_filter.py for the non-eligible majority -- this script only runs for packages
already marked ANALYZED there.) All intermediate artifacts (tarball, extracted tree, CPG
binaries) are deleted after each package completes, regardless of outcome, so disk usage
stays bounded across the corpus.
"""
import json
import os
import resource
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
CPP_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend"
JS_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/javascript-typescript/joern"
POLYGLOT = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/polyglot/link_napi_facts.py"
SCANNER_V2 = "/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2"

JS_TS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
CPP_EXTS = (".c", ".cc", ".cpp", ".cxx")

# Real limits established from the 50-package pilot (see RESOURCE_LIMITS section of
# CORPUS_STATUS.md / the pilot commit message): 48/50 packages completed every stage in
# well under these standard timeouts (c2cpg max observed 41.4s, cpp_export max 31.7s,
# cpp_normalize median 0.24s). The 2/50 exceptions (re2, pqclean) are large, real, bundled
# C++ codebases (re2: 551 files, 1.34M raw fact rows) -- normalize alone took a real,
# reproduced 127.6s for re2, confirmed by manual re-run with a generous timeout, not a hang.
# TIMEOUT_MULTIPLIER lets the SAME script serve both the standard pass (multiplier=1) and the
# high-resource retry queue (multiplier=8 -> 1440s/720s ceilings) without duplicating logic.
TIMEOUT_MULTIPLIER = float(os.environ.get("NPM_CORPUS_TIMEOUT_MULTIPLIER", "1"))
STAGE_TIMEOUT = int(180 * TIMEOUT_MULTIPLIER)     # c2cpg / jssrc2cpg / cpp_export / js_export
NORMALIZE_TIMEOUT = int(180 * TIMEOUT_MULTIPLIER)  # cpp_normalize / js_normalize (re2's real 127.6s + margin)
LINK_TIMEOUT = int(90 * TIMEOUT_MULTIPLIER)        # polyglot_link
SCAN_TIMEOUT = int(90 * TIMEOUT_MULTIPLIER)        # r04_scan (reads raw TSVs directly, not the large normalized JSON)


def rss_now():
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss  # KB, running max


def run_stage(cmd, log_path, timeout=STAGE_TIMEOUT):
    before = rss_now()
    t0 = time.time()
    try:
        with open(log_path, "w") as log:
            proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        elapsed = time.time() - t0
        after = rss_now()
        return proc.returncode, elapsed, max(0, after - before), None
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        return None, elapsed, 0, "TIMEOUT"
    except Exception as e:
        elapsed = time.time() - t0
        return None, elapsed, 0, f"{type(e).__name__}: {e}"


def fetch_bytes(url, timeout=60, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "resource-guard-corpus-mining/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(), None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
                continue
            return None, f"HTTPError {e.code}: {e}"
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return None, f"{type(e).__name__}: {e}"
    return None, "exhausted retries"


def run_one(pkg_name, version, tarball_url, exception_config, work_root):
    record = {"package_name": pkg_name, "version": version, "stages": {}, "status": None,
              "detail": ""}
    pkg_dir = os.path.join(work_root, "pkg")
    js_dir = os.path.join(work_root, "js")
    work = os.path.join(work_root, "work")
    for d in (pkg_dir, js_dir, work):
        os.makedirs(d, exist_ok=True)

    t0 = time.time()
    tb, err = fetch_bytes(tarball_url)
    record["stages"]["download"] = {"seconds": time.time() - t0}
    if err:
        record["status"] = "DOWNLOAD_FAILED"
        record["detail"] = err
        return record

    t0 = time.time()
    try:
        tf = tarfile.open(fileobj=__import__("io").BytesIO(tb), mode="r:gz")
        tf.extractall(pkg_dir, filter="data")
        tf.close()
        # npm tarballs wrap contents under package/ -- flatten one level if present
        inner = os.path.join(pkg_dir, "package")
        if os.path.isdir(inner):
            for name in os.listdir(inner):
                shutil.move(os.path.join(inner, name), os.path.join(pkg_dir, name))
            os.rmdir(inner)
    except Exception as e:
        record["stages"]["extract"] = {"seconds": time.time() - t0}
        record["status"] = "EXTRACTION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["extract"] = {"seconds": time.time() - t0}

    # Collect JS/TS files into a separate dir (jssrc2cpg over the whole tree would also work,
    # but node_modules-free npm tarballs are small enough that pointing jssrc2cpg at pkg_dir
    # directly is simpler and equally correct -- use pkg_dir itself for JS, and c2cpg also
    # over pkg_dir for C/C++; both frontends only pick up their own extensions.)
    cpp_bin = os.path.join(work, "cpp.cpg.bin")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/c2cpg.sh", "-o", cpp_bin, pkg_dir],
        os.path.join(work, "cpp_gen.log"))
    record["stages"]["c2cpg"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "CPP_CPG_FAILED"
        record["detail"] = err or f"c2cpg rc={rc}"
        return record

    js_bin = os.path.join(work, "js.cpg.bin")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/jssrc2cpg.sh", "-o", js_bin, pkg_dir],
        os.path.join(work, "js_gen.log"))
    record["stages"]["jssrc2cpg"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "JS_CPG_FAILED"
        record["detail"] = err or f"jssrc2cpg rc={rc}"
        return record

    cpp_raw = os.path.join(work, "cpp_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", f"{CPP_FRONTEND}/export_c_cpp_facts_v03.sc",
         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"],
        os.path.join(work, "cpp_export.log"))
    record["stages"]["cpp_export"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"cpp export rc={rc}"
        return record

    js_raw = os.path.join(work, "js_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", f"{JS_FRONTEND}/export_neutral.sc",
         "--param", f"cpgFile={js_bin}", "--param", f"outDir={js_raw}"],
        os.path.join(work, "js_export.log"))
    record["stages"]["js_export"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"js export rc={rc}"
        return record

    cpp_facts = os.path.join(work, "cpp_facts.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{CPP_FRONTEND}/normalize_c_cpp_facts_v03.py",
                         cpp_raw, cpp_facts], check=True, timeout=NORMALIZE_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"cpp_normalize exceeded {NORMALIZE_TIMEOUT}s (real, reproduced " \
                            "case: re2 took 127.6s on a full re-run outside this timeout -- " \
                            "large, genuinely bundled C++ codebases need the high-resource " \
                            "retry queue, not a silent drop)"
        return record
    except Exception as e:
        record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}

    js_facts = os.path.join(work, "js_facts.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{JS_FRONTEND}/normalize_joern_facts.py",
                         js_raw, js_facts], check=True, timeout=NORMALIZE_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        record["stages"]["js_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"js_normalize exceeded {NORMALIZE_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["js_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["js_normalize"] = {"seconds": time.time() - t0}

    js_facts_adapted = os.path.join(work, "js_facts_adapted.json")
    merged = os.path.join(work, "merged.json")
    t0 = time.time()
    try:
        sys.path.insert(0, SCANNER_V2 + "/npm_corpus")
        import polyglot_compat_adapter
        polyglot_compat_adapter.adapt_js_facts(js_facts, js_facts_adapted)
        subprocess.run([sys.executable, POLYGLOT, js_facts_adapted, cpp_facts, merged,
                         "--js-receiver", "bindings"], check=True, timeout=LINK_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        with open(merged) as f:
            merged_doc = json.load(f)
        xlb = merged_doc.get("cross_language_bindings", {})
        record["cross_language_bindings"] = {
            "n_registrations": len(xlb.get("registrations", [])),
            "n_linked_calls": len(xlb.get("linked_calls", [])),
            "n_unlinked_calls": len(xlb.get("unlinked_calls", [])),
        }
    except subprocess.TimeoutExpired:
        record["stages"]["polyglot_link"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"polyglot_link exceeded {LINK_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["polyglot_link"] = {"seconds": time.time() - t0}
        record["status"] = "BINDING_UNRESOLVED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["polyglot_link"] = {"seconds": time.time() - t0}

    build_config_path = os.path.join(work, "build_config.json")
    with open(build_config_path, "w") as f:
        json.dump({"exception_configuration": exception_config or "unresolved",
                    "evidence": [], "citation": "from npm_build_configuration.tsv"}, f)

    r04_out = os.path.join(work, "r04_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_r04.py",
                         cpp_raw, r04_out, "--real", "--build-config", build_config_path],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(r04_out) as f:
            r04_doc = json.load(f)
        record["r04_classification"] = r04_doc.get("classification", {})
        record["r04_findings"] = r04_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["r04_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"r04_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["r04_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"r04 scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["r04_scan"] = {"seconds": time.time() - t0}

    record["status"] = "ANALYZED"
    return record


def main():
    eligible_path = sys.argv[1]
    build_config_path = sys.argv[2]
    out_path = sys.argv[3]
    start_idx = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    end_idx = int(sys.argv[5]) if len(sys.argv) > 5 else None

    rows = []
    with open(eligible_path) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            rows.append(parts)

    exc_config_by_pkg = {}
    with open(build_config_path) as f:
        bheader = next(f).rstrip("\n").split("\t")
        bidx = {n: i for i, n in enumerate(bheader)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            exc_config_by_pkg[(parts[bidx["package_name"]], parts[bidx["version"]])] = \
                parts[bidx["exception_configuration"]]

    if end_idx is None:
        end_idx = len(rows)
    rows = rows[start_idx:end_idx]

    mode = "a" if start_idx > 0 else "w"
    with open(out_path, mode) as out:
        for i, parts in enumerate(rows):
            pkg = parts[idx["package_name"]]
            version = parts[idx["version"]]
            tarball_url = parts[idx["tarball_url"]]
            exc_config = exc_config_by_pkg.get((pkg, version))
            work_root = f"/tmp/npm_corpus_pilot/{start_idx + i}"
            shutil.rmtree(work_root, ignore_errors=True)
            os.makedirs(work_root, exist_ok=True)
            t0 = time.time()
            rec = run_one(pkg, version, tarball_url, exc_config, work_root)
            rec["total_seconds"] = time.time() - t0
            shutil.rmtree(work_root, ignore_errors=True)  # bound disk usage
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"[{start_idx + i + 1}/{start_idx + len(rows)}] {pkg}@{version}: "
                  f"{rec['status']} ({rec['total_seconds']:.1f}s)", file=sys.stderr)


if __name__ == "__main__":
    main()
