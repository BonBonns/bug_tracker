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

R06 CHANGE (this file only -- `run_pipeline_one.py` itself, hash `1c031795a3383ff63aa1a22e
382daeae`, stays frozen and untouched; this is a new, separate, byte-for-byte-copy-plus-fix
file, same lineage discipline as every prior R0N revision in this project): before deleting
work_root, write a minimal compressed per-package evidence bundle via
`evidence_bundle.write_evidence_bundle()` -- see that module's own docstring for exactly what
is and is not preserved and why. This is the fix for the real, disclosed gap found auditing
this pipeline: the frozen version bounds disk usage by deleting EVERYTHING, which also
silently deletes the only path to a verdict-only rerun (no saved raw facts for R04/R05/R06
to re-scan without a full Joern rebuild). CPG binaries and the extracted source tree are
still deleted -- only real scanner-consumed evidence is kept, compressed, per package.

REDOS INTEGRATION (roadmap step 8, first of 4 JS/TS classes): after the Nan stage, this file also
runs ReDoS (frozen, merged: export_redos_npm_integ_r02.sc + redos_verdict.py) as part of this same
per-package chain, reusing the js_bin CPG and pkg_dir this function already builds/extracts above
rather than the standalone study/redos_npm/pilot25/run_pilot25_r02.py's own from-scratch
download+build. Ports that script's own real run_one() algorithm (entrypoint-coverage correction
via frontend_coverage_check.py, imported and never modified, then the R02 producer, then the
frozen reducer) in place -- see the inline comments at the ReDoS stage block below for the one
real structural difference (pass 1 is never rebuilt: js_bin already IS it).
"""
import hashlib
import json
import os
import resource
import shutil
import subprocess
import sys
import tarfile

from evidence_bundle import write_evidence_bundle
from extract_build_config import classify_target_aware
import time
import urllib.error
import urllib.request

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
CPP_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend"
JS_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/javascript-typescript/joern"
POLYGLOT = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/polyglot/link_napi_facts.py"
SCANNER_V2 = "/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2"

# REDOS INTEGRATION (roadmap step 8): the frozen R02 producer + reducer, and the audit dir
# holding frontend_coverage_check.py -- all reused verbatim from
# study/redos_npm/pilot25/run_pilot25_r02.py's own already-validated paths, never modified here.
R02_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/"
                "producers/export_redos_npm_integ_r02.sc")
REDOS_VERDICT = os.path.join(SCANNER_V2, "redos_verdict.py")
REDOS_FCC_AUDIT_DIR = os.path.join(SCANNER_V2, "study", "redos_npm", "pilot25", "audit")

# PATH TRAVERSAL INTEGRATION (roadmap step 8, second of 4 JS/TS classes): the frozen, merged
# shared npm-source-identity producer (its own latest revision, R02 -- restores Meteor.methods/
# message-item ingress recognition, see NPM_SOURCE_IDENTITY_R02_IMPLEMENTATION.md) MUST run
# against the SAME js_bin BEFORE Path Traversal's own R02 producer, writing source_origin_facts.tsv
# into the SAME rawDir Path Traversal's own producer reads from -- both required upstream steps,
# never invoked by Path Traversal's own producer itself (see that file's own header comment for
# the full disclosure of this dependency). All three files (frozen; never modified here).
NPM_SOURCE_IDENTITY_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                                 "tchecker-property-adjudicator/producers/"
                                 "export_npm_source_identity_r02.sc")
PATH_TRAVERSAL_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                            "tchecker-property-adjudicator/producers/"
                            "export_path_traversal_integ_r02.sc")
PATH_TRAVERSAL_VERDICT = os.path.join(SCANNER_V2, "path_traversal_verdict.py")

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


def fetch_json(url, timeout=30, retries=3):
    raw, err = fetch_bytes(url, timeout=timeout, retries=retries)
    if err:
        return None, err
    try:
        return json.loads(raw), None
    except Exception as e:
        return None, f"bad JSON from {url}: {type(e).__name__}: {e}"


# --- Header-staging correction (NPM-CORPUS-HDR-FIX) -------------------------------------------
# Real, confirmed root cause (FINDINGS_REVIEW.md): every package in the corpus declares
# node-addon-api (sometimes nan) as an npm DEPENDENCY and #includes its header, but no
# package's own tarball vendors that header -- it is meant to resolve from
# node_modules/<dep>/ after `npm install`, which this pipeline never ran. c2cpg therefore
# could not resolve ANY Napi:: static-factory call, corpus-wide. This section fetches ONLY
# the specific declared dependency's own header-only package (not a full `npm install`: no
# scripts run, no transitive tree, no unrelated native deps built) and hands its extracted
# directory to c2cpg via --include, so #include <napi.h> / #include <nan.h> resolve exactly
# as they would after a real install.
#
# Disclosed scope, stated precisely -- this is NOT a full npm resolver:
#  - Only "node-addon-api" and "nan" are staged (the two node-addon-api-style header-only C++
#    wrapper libraries actually observed in this corpus's binding_evidence). Raw N-API usage
#    via <node_api.h>/<js_native_api.h> is NOT covered -- those are Node.js's own core
#    headers, not distributed via any npm package, and staging them would require vendoring a
#    matching Node.js headers tarball, a separate, larger undertaking not attempted here.
#  - Version resolution is a minimal, hand-written npm range matcher (exact/^/~/>=/>/<=/</*),
#    not a byte-for-byte reimplementation of npm's own resolver. It excludes prereleases and
#    falls back to the package's "latest" dist-tag if the range can't be parsed or nothing in
#    the registry's version list satisfies it -- a real, disclosed approximation, not a
#    silent guess: every resolution (or failure) is recorded in the package's own
#    `header_staging` evidence field.
#  - Staging is fail-OPEN: a missing package.json, an unresolvable range, or a failed fetch
#    means that dependency is simply not staged (recorded as such) -- c2cpg still runs
#    exactly as it did before this fix, so this correction can only ADD resolution, never
#    remove or regress any package's prior result.

NATIVE_HEADER_DEPS = ("node-addon-api", "nan")


def _parse_semver(v):
    # Strips build metadata (+...) and returns (major, minor, patch, prerelease_or_None).
    v = v.strip().lstrip("v")
    core = v.split("+", 1)[0]
    if "-" in core:
        core, pre = core.split("-", 1)
    else:
        pre = None
    parts = (core.split(".") + ["0", "0", "0"])[:3]
    try:
        major, minor, patch = (int(p) for p in parts)
    except ValueError:
        return None
    return (major, minor, patch, pre)


def _range_satisfied(ver, range_spec):
    # ver: parsed (major, minor, patch, prerelease) tuple, already prerelease-excluded by the
    # caller. Supports the common single-clause forms actually seen in real package.json
    # dependency fields: exact "X.Y.Z", "^X.Y.Z", "~X.Y.Z", ">=X.Y.Z", ">X.Y.Z", "<=X.Y.Z",
    # "<X.Y.Z", "*"/""/"latest". Anything else (OR ranges, hyphen ranges, "x" wildcards) is
    # NOT parsed -- the caller treats that as "unresolvable" and falls back to dist-tags.latest.
    spec = range_spec.strip()
    if spec in ("", "*", "latest"):
        return True
    for op, cmp_fn in ((">=", lambda a, b: a >= b), ("<=", lambda a, b: a <= b),
                        (">", lambda a, b: a > b), ("<", lambda a, b: a < b)):
        if spec.startswith(op):
            target = _parse_semver(spec[len(op):])
            return target is not None and cmp_fn(ver[:3], target[:3])
    if spec.startswith("^"):
        target = _parse_semver(spec[1:])
        if target is None:
            return None
        maj, minr, pat, _ = target
        if maj > 0:
            return (maj, minr, pat) <= ver[:3] < (maj + 1, 0, 0)
        if minr > 0:
            return (0, minr, pat) <= ver[:3] < (0, minr + 1, 0)
        return (0, 0, pat) <= ver[:3] <= (0, 0, pat)
    if spec.startswith("~"):
        target = _parse_semver(spec[1:])
        if target is None:
            return None
        maj, minr, pat, _ = target
        return (maj, minr, pat) <= ver[:3] < (maj, minr + 1, 0)
    target = _parse_semver(spec)
    if target is not None:
        return ver[:3] == target[:3]
    return None  # unrecognized range shape -- caller falls back to latest


def resolve_npm_dep_version(dep_name, range_spec):
    """Returns (resolved_version_or_None, tarball_url_or_None, note)."""
    meta, err = fetch_json(f"https://registry.npmjs.org/{dep_name}")
    if err:
        return None, None, f"metadata fetch failed: {err}"
    latest_tag = meta.get("dist-tags", {}).get("latest")
    versions = meta.get("versions", {})
    candidates = []
    for v, info in versions.items():
        parsed = _parse_semver(v)
        if parsed is None or parsed[3] is not None:  # skip unparsed / prerelease
            continue
        sat = _range_satisfied(parsed, range_spec)
        if sat is None:
            candidates = None  # unrecognized range shape -- abandon range matching entirely
            break
        if sat:
            candidates.append((parsed[:3], v))
    if candidates:
        candidates.sort()
        resolved = candidates[-1][1]
        note = f"range '{range_spec}' resolved to {resolved} (highest satisfying release)"
    elif latest_tag and latest_tag in versions:
        resolved = latest_tag
        note = f"range '{range_spec}' unresolvable/unsatisfied -- fell back to latest ({resolved})"
    else:
        return None, None, f"no satisfying version and no usable latest tag for '{range_spec}'"
    tarball = versions.get(resolved, {}).get("dist", {}).get("tarball")
    if not tarball:
        return None, None, f"resolved {resolved} but no dist.tarball in registry metadata"
    return resolved, tarball, note


def stage_native_dep_headers(pkg_dir, work_root):
    """Fetches and extracts node-addon-api/nan (whichever this package actually declares) into
    work_root/headers/<dep>/, returning (include_dirs, evidence_list) for c2cpg --include."""
    include_dirs = []
    evidence = []
    pkg_json_path = os.path.join(pkg_dir, "package.json")
    if not os.path.isfile(pkg_json_path):
        return include_dirs, [{"dep": None, "staged": False, "note": "no package.json found"}]
    try:
        with open(pkg_json_path) as f:
            pkg_json = json.load(f)
    except Exception as e:
        return include_dirs, [{"dep": None, "staged": False,
                                 "note": f"package.json unreadable: {type(e).__name__}: {e}"}]
    declared = {}
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        declared.update(pkg_json.get(field) or {})
    for dep in NATIVE_HEADER_DEPS:
        if dep not in declared:
            continue
        range_spec = declared[dep]
        resolved, tarball, note = resolve_npm_dep_version(dep, range_spec)
        if not tarball:
            evidence.append({"dep": dep, "declared_range": range_spec, "staged": False,
                              "note": note})
            continue
        tb, err = fetch_bytes(tarball)
        if err:
            evidence.append({"dep": dep, "declared_range": range_spec, "resolved_version":
                              resolved, "staged": False, "note": f"tarball fetch failed: {err}"})
            continue
        dep_dir = os.path.join(work_root, "headers", dep)
        try:
            os.makedirs(dep_dir, exist_ok=True)
            tf = tarfile.open(fileobj=__import__("io").BytesIO(tb), mode="r:gz")
            tf.extractall(dep_dir, filter="data")
            tf.close()
            inner = os.path.join(dep_dir, "package")
            if os.path.isdir(inner):
                for name in os.listdir(inner):
                    shutil.move(os.path.join(inner, name), os.path.join(dep_dir, name))
                os.rmdir(inner)
        except Exception as e:
            evidence.append({"dep": dep, "declared_range": range_spec, "resolved_version":
                              resolved, "staged": False,
                              "note": f"extract failed: {type(e).__name__}: {e}"})
            continue
        include_dirs.append(dep_dir)
        evidence.append({"dep": dep, "declared_range": range_spec, "resolved_version": resolved,
                          "staged": True, "note": note})
    if not evidence:
        evidence.append({"dep": None, "staged": False,
                          "note": "package.json present but declares neither node-addon-api nor nan"})
    return include_dirs, evidence


def find_and_classify_gyp_targets(pkg_dir):
    """R06 TARGET-SCOPING FIX -- locates this package's own real binding.gyp (searched from
    pkg_dir's root, shallowest match first -- real corpus packages observed so far keep it at
    the package root; a bounded recursive search catches the rare nested case without an
    unbounded walk) and returns (relative_gyp_path, per_target_list) via the real,
    already-tested `classify_target_aware()` parser, or (None, None) if no real binding.gyp
    exists in this package at all (a cmake/meson/gn-only package, or no native build file --
    both real, disclosed cases; the caller/scanner then falls back to the package-wide
    npm_build_configuration.tsv value, never guesses per-target)."""
    matches = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        if "binding.gyp" in filenames:
            rel_dir = os.path.relpath(dirpath, pkg_dir)
            depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
            matches.append((depth, os.path.join(dirpath, "binding.gyp")))
    if not matches:
        return None, None
    matches.sort(key=lambda t: t[0])
    gyp_path = matches[0][1]
    try:
        with open(gyp_path, "rb") as f:
            content = f.read()
    except Exception:
        return None, None
    per_target = classify_target_aware(content)
    rel_path = os.path.relpath(gyp_path, pkg_dir)
    return rel_path, (per_target or None)


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
    # R06 BUNDLE INTEGRITY (item 4): real sha256 of the actual downloaded tarball bytes,
    # carried through on the record so main()'s own write_evidence_bundle() call can cite it
    # without re-fetching or re-hashing.
    record["tarball_sha256"] = hashlib.sha256(tb).hexdigest()

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

    # NPM-CORPUS-HDR-FIX: stage this package's own declared node-addon-api/nan headers (see
    # stage_native_dep_headers's docstring for the disclosed scope) before c2cpg runs, so
    # #include <napi.h> resolves instead of falling back to <unresolvedNamespace> for every
    # Napi:: call, as it did corpus-wide before this fix (FINDINGS_REVIEW.md).
    t0 = time.time()
    include_dirs, header_evidence = stage_native_dep_headers(pkg_dir, work_root)
    record["header_staging"] = header_evidence
    record["stages"]["header_staging"] = {"seconds": time.time() - t0,
                                            "n_staged": len(include_dirs)}

    # Collect JS/TS files into a separate dir (jssrc2cpg over the whole tree would also work,
    # but node_modules-free npm tarballs are small enough that pointing jssrc2cpg at pkg_dir
    # directly is simpler and equally correct -- use pkg_dir itself for JS, and c2cpg also
    # over pkg_dir for C/C++; both frontends only pick up their own extensions.)
    cpp_bin = os.path.join(work, "cpp.cpg.bin")
    c2cpg_cmd = [f"{JOERN_HOME}/c2cpg.sh", "-o", cpp_bin]
    for d in include_dirs:
        c2cpg_cmd += ["--include", d]
    # RESOURCE-GUARD-R05-HDR-FIX2: real napi.h #errors out (Exception support not detected)
    # unless NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS is predefined -- confirmed real,
    # see HDR_FIX_STATUS.md. Use this package's OWN already-extracted exception_config where
    # known ("disabled"/"enabled"); for "unresolved"/"conflict"/missing, define
    # NAPI_DISABLE_CPP_EXCEPTIONS anyway AS A PARSING AID ONLY -- disclosed, deliberate: this
    # maximizes real structural resolution quality (most of the corpus's KNOWN values are
    # "disabled" -- CORPUS_STATUS.md: 140 disabled vs 19 enabled -- and Cartesi/sqlite3/
    # gjsify-node-gi are all real "disabled" packages) without smuggling in an unjustified
    # verdict: R04/R05's own APPLICABILITY GATE reads this package's REAL build_config.json
    # independently and still correctly abstains (BUILD_CONFIGURATION_UNRESOLVED/_CONFLICT)
    # for any package whose real evidence doesn't establish "disabled" -- this parsing-time
    # define never substitutes for that separate, already-existing check.
    c2cpg_cmd += ["--define", "NAPI_CPP_EXCEPTIONS" if exception_config == "enabled"
                  else "NAPI_DISABLE_CPP_EXCEPTIONS"]
    c2cpg_cmd.append(pkg_dir)
    rc, secs, mem, err = run_stage(
        c2cpg_cmd,
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

    # R06 TARGET-SCOPING FIX: capture this package's own real binding.gyp (already extracted
    # into pkg_dir) and its real per-target classification, so the scanner can associate each
    # finding's own source file with the SPECIFIC target that compiles it, rather than the
    # package-wide npm_build_configuration.tsv value alone. package_wide is kept as the
    # required fallback for a non-gyp (cmake/meson/gn) package, or if no binding.gyp was found
    # -- never silently dropped, always present for that disclosed scope boundary.
    t0 = time.time()
    gyp_path, gyp_targets = find_and_classify_gyp_targets(pkg_dir)
    record["stages"]["gyp_target_scoping"] = {"seconds": time.time() - t0,
                                                "gyp_path": gyp_path,
                                                "n_targets": len(gyp_targets) if gyp_targets else 0}
    build_config_path = os.path.join(work, "build_config.json")
    with open(build_config_path, "w") as f:
        json.dump({"schema": "build_config/2",
                    "exception_configuration": exception_config or "unresolved",
                    "evidence": [], "citation": "from npm_build_configuration.tsv",
                    "gyp_path": gyp_path, "gyp_targets": gyp_targets}, f)

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

    # RESOURCE-GUARD-R05: run alongside R04, not instead of it -- R05's own matching path for
    # already-resolved calls is byte-for-byte R04's (see resource_guard_verdict_r05.py's own
    # module docstring), so this is a strict superset; keeping BOTH outputs, separately keyed,
    # gives a direct per-package A/B record of exactly what recovery adds, rather than
    # silently replacing R04's own recorded numbers.
    r05_out = os.path.join(work, "r05_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_r05.py",
                         cpp_raw, r05_out, "--real", "--build-config", build_config_path],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(r05_out) as f:
            r05_doc = json.load(f)
        record["r05_classification"] = r05_doc.get("classification", {})
        record["r05_findings"] = r05_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["r05_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"r05_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["r05_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"r05 scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["r05_scan"] = {"seconds": time.time() - t0}

    # RESOURCE-GUARD-R06: run alongside R04/R05, not instead of them -- same A/B discipline.
    # R06's own two corrections (target-scoped build config, source-boundary gate) are new,
    # real behavior; keeping R04/R05's own outputs unchanged lets a reader see exactly what
    # R06 adds/removes relative to both, never silently replacing prior numbers.
    r06_out = os.path.join(work, "r06_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_r06.py",
                         cpp_raw, r06_out, "--real", "--build-config", build_config_path],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(r06_out) as f:
            r06_doc = json.load(f)
        record["r06_classification"] = r06_doc.get("classification", {})
        record["r06_findings"] = r06_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["r06_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"r06_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["r06_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"r06 scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["r06_scan"] = {"seconds": time.time() - t0}

    # NAN CAPABILITY (frozen, study/nan_capability/NAN_CAPABILITY_FREEZE.md): a real, standalone
    # Resource Guard variant for the Nan binding family -- run alongside R04/R05/R06, never
    # replacing them (imports nothing from that lineage, carries no build-config applicability
    # premise of its own; see resource_guard_verdict_nan.py's own module docstring). Uses
    # js_raw directly (the raw jssrc2cpg export this function already built above, before any
    # cleanup) -- never js_facts.json, which is a normalized summary this scanner's own
    # load_js_raw() does not read. Never gated on `exception_config`/build_config_path at all.
    nan_out = os.path.join(work, "nan_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_nan.py",
                         cpp_raw, js_raw, nan_out],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(nan_out) as f:
            nan_doc = json.load(f)
        record["nan_classification"] = nan_doc.get("classification", {})
        record["nan_findings"] = nan_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["nan_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"nan_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["nan_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"nan scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["nan_scan"] = {"seconds": time.time() - t0}

    # REDOS INTEGRATION (roadmap step 8, first of 4 JS/TS classes): ReDoS is fully frozen/merged
    # (R02, export_redos_npm_integ_r02.sc + redos_verdict.py) and already validated standalone by
    # study/redos_npm/pilot25/run_pilot25_r02.py -- this ports that script's own real run_one()
    # algorithm in place, reusing pkg_dir and js_bin (both already built above) instead of
    # re-downloading/re-building a separate JS-only CPG. Never modifies frontend_coverage_check.py,
    # export_redos_npm_integ_r02.sc, or redos_verdict.py -- orchestration only, exactly as
    # run_pilot25_r02.py's own module docstring states about itself.
    #
    # Entrypoint-coverage correction (the real reason this exists: jssrc2cpg's own default ignore
    # rules -- a folder-name list including "dist", a filename-suffix regex, or an unanchored
    # node_modules substring match -- can silently drop a package.json-resolved entrypoint before
    # a single CPG node for it ever exists; frontend_coverage_check.py's own module docstring has
    # the full, evidence-backed story). run_pilot25_r02.py always builds its own CPG as "pass 1"
    # then checks it; here js_bin ALREADY IS that pass-1 CPG (built above, before cpp/js export),
    # so pass 1 is never rebuilt -- fcc.list_cpg_files() is checked directly against js_bin, and a
    # pass-2 rebuild (fcc.stage_recovered_source + fcc.build_cpg, identical to run_pilot25_r02.py's
    # own pass-2 logic) only happens if something resolved is genuinely missing. In the common
    # case (nothing missing) js_bin is reused as-is, with zero extra CPG build.
    t0 = time.time()
    try:
        sys.path.insert(0, REDOS_FCC_AUDIT_DIR)
        import frontend_coverage_check as fcc  # noqa: E402 -- reused, never modified

        final_cpg = js_bin
        redos_frontend_coverage = {"resolved_entrypoints": [], "n_missing_entrypoints": 0,
                                    "missing_entrypoints": [], "correction_applied": False}
        pkg_json_path = fcc.find_package_json(pkg_dir)
        if pkg_json_path is not None:
            with open(pkg_json_path) as f:
                pkg_doc = json.load(f)
            entrypoints = fcc.resolve_entrypoints(pkg_doc)
            # pkg_dir is ALREADY flattened (the npm tarball's own "package/" wrapper was stripped
            # above, unlike run_pilot25_r02.py's own src_dir, which keeps it) -- pkg_root_rel is
            # therefore "" here in the common case, so entrypoint relpaths need no prefix; this is
            # exactly the pkg_root_rel == "." case run_pilot25_r02.py's own logic already handles,
            # just the common case here instead of the exception there.
            pkg_root_rel = os.path.relpath(os.path.dirname(pkg_json_path), pkg_dir).replace(os.sep, "/")
            if pkg_root_rel == ".":
                pkg_root_rel = ""

            def to_pkg_dir_rel(ep, _prefix=pkg_root_rel):
                return (_prefix + "/" + ep) if _prefix else ep

            cpg1_files_set = set(fcc.list_cpg_files(js_bin)[0])
            missing = []
            for ep in entrypoints:
                relpath = to_pkg_dir_rel(ep)
                if relpath in cpg1_files_set:
                    continue
                abspath = os.path.join(pkg_dir, *relpath.split("/"))
                if not os.path.isfile(abspath):
                    continue
                reason = fcc.classify_ignore_reason(relpath, abspath)
                if reason:
                    missing.append((relpath, reason))
            redos_frontend_coverage["resolved_entrypoints"] = entrypoints
            redos_frontend_coverage["n_missing_entrypoints"] = len(missing)
            redos_frontend_coverage["missing_entrypoints"] = [
                {"relpath": r, "reason": rs} for r, rs in missing]
            if missing:
                staged_dir, recovered_map = fcc.stage_recovered_source(pkg_dir, missing)
                cpg2 = os.path.join(work, "redos_pass2.cpg.bin")
                ok2, log2 = fcc.build_cpg(staged_dir, cpg2)
                if ok2:
                    cpg2_files_set = set(fcc.list_cpg_files(cpg2)[0])
                    still_missing = [(r, rs) for r, rs in missing
                                      if recovered_map.get(r) not in cpg2_files_set]
                    redos_frontend_coverage["correction_applied"] = True
                    redos_frontend_coverage["recovered_path_map"] = recovered_map
                    redos_frontend_coverage["still_missing_after_correction"] = still_missing
                    final_cpg = cpg2
                else:
                    redos_frontend_coverage["correction_applied"] = False
                    redos_frontend_coverage["correction_error"] = log2[-1000:]
        record["redos_frontend_coverage"] = redos_frontend_coverage
    except Exception as e:
        record["stages"]["redos_frontend_coverage"] = {"seconds": time.time() - t0}
        record["status"] = "EXPORT_FAILED"
        record["detail"] = f"redos frontend coverage check failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["redos_frontend_coverage"] = {"seconds": time.time() - t0}

    # R02 producer -- same joern-script shape as cpp_export/js_export above (run_stage, checked
    # via rc/err). redos_raw and pkg_dir (passed to the reducer next) are both already absolute
    # (work_root is built from an absolute "/tmp/npm_corpus_pilot/<i>" literal in main() below,
    # and pkg_dir/work are os.path.join()'d from it) -- required by redos_verdict.py's own
    # subprocess.run(..., cwd=ADJUDICATOR_DIR, ...) call to adjudicate_js.py, which silently
    # produces ADJUDICATOR_RUN_FAILED on every sink if handed a relative path instead.
    redos_raw = os.path.join(work, "redos_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", R02_PRODUCER,
         "--param", f"cpgFile={final_cpg}", "--param", f"rawDir={redos_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "redos_producer.log"))
    record["stages"]["redos_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"redos producer rc={rc}"
        return record

    # Reducer (frozen, unmodified): exactly 3 positional args, both redos_raw and pkg_dir passed
    # absolute (see comment above).
    redos_out = os.path.join(work, "redos_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, REDOS_VERDICT, redos_raw, pkg_dir, redos_out],
                         check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
        with open(redos_out) as f:
            redos_doc = json.load(f)
        record["redos_classification"] = redos_doc.get("classification", {})
        record["redos_findings"] = redos_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["redos_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"redos_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["redos_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"redos scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["redos_scan"] = {"seconds": time.time() - t0}

    # PATH TRAVERSAL INTEGRATION (roadmap step 8, second of 4 JS/TS classes): two producers, in
    # order, into the SAME rawDir -- the shared npm-source-identity producer first (writes
    # source_origin_facts.tsv), then Path Traversal's own R02 producer (reads it, writes
    # source_facts.tsv/sink_abstentions.tsv/etc.). Reuses js_bin (already built above) -- Path
    # Traversal's own sink identification is structural and needs no entrypoint-coverage
    # correction of its own (unlike ReDoS, it never re-derives export/source logic that depends on
    # jssrc2cpg's own default-ignore rules the way ReDoS's frontend_coverage_check.py corrects for).
    pt_raw = os.path.join(work, "pt_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", NPM_SOURCE_IDENTITY_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={pt_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "npm_source_identity_producer.log"))
    record["stages"]["npm_source_identity_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"npm_source_identity producer rc={rc}"
        return record

    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", PATH_TRAVERSAL_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={pt_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "path_traversal_producer.log"))
    record["stages"]["path_traversal_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"path_traversal producer rc={rc}"
        return record

    # Reducer (frozen except for the sink_abstentions consumption fix): 3 positional args, both
    # pt_raw and pkg_dir passed absolute (same real landmine as redos_verdict.py -- a relative
    # path here silently produces ADJUDICATOR_RUN_FAILED on every sink instead of a real error).
    pt_out = os.path.join(work, "path_traversal_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, PATH_TRAVERSAL_VERDICT, pt_raw, pkg_dir, pt_out],
                         check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
        with open(pt_out) as f:
            pt_doc = json.load(f)
        record["path_traversal_classification"] = pt_doc.get("classification", {})
        record["path_traversal_findings"] = pt_doc.get("findings", [])
        record["path_traversal_abstentions"] = pt_doc.get("abstentions", [])
    except subprocess.TimeoutExpired:
        record["stages"]["path_traversal_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"path_traversal_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["path_traversal_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"path_traversal scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["path_traversal_scan"] = {"seconds": time.time() - t0}

    record["status"] = "ANALYZED"
    return record


def main():
    if len(sys.argv) < 5:
        raise SystemExit(
            "usage: run_pipeline_one_r06.py <eligible_path> <build_config_path> <out_path> "
            "<bundle_dir> [start_idx] [end_idx]\n"
            "bundle_dir is required and explicit -- the persistent evidence-bundle output "
            "directory (see evidence_bundle.py). Not optional: this is the whole point of "
            "the R06 persistence fix over the frozen run_pipeline_one.py."
        )
    eligible_path = sys.argv[1]
    build_config_path = sys.argv[2]
    out_path = sys.argv[3]
    bundle_dir = sys.argv[4]
    start_idx = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    end_idx = int(sys.argv[6]) if len(sys.argv) > 6 else None

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
            # R06 FIX: persist a minimal compressed evidence bundle BEFORE deleting work_root --
            # see evidence_bundle.py for exactly what is (and is not) kept. Bundling failure is
            # recorded, never silently swallowed, and never blocks the corpus loop from
            # continuing (a bundling bug must not turn into a lost package result).
            try:
                bundle_path, bundle_manifest = write_evidence_bundle(
                    work_root, bundle_dir, pkg, version,
                    tarball_sha256=rec.get("tarball_sha256"),
                    pipeline_status=rec.get("status"))
                rec["evidence_bundle"] = {
                    "bundle_path": bundle_path,
                    "included": bundle_manifest["included"],
                    "missing": bundle_manifest["missing"],
                    "compressed_bytes": bundle_manifest.get("compressed_bytes"),
                    "completeness_status": bundle_manifest.get("completeness_status"),
                }
            except Exception as e:
                rec["evidence_bundle"] = {"error": f"{type(e).__name__}: {e}"}
            shutil.rmtree(work_root, ignore_errors=True)  # bound disk usage -- CPG/work dir only
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"[{start_idx + i + 1}/{start_idx + len(rows)}] {pkg}@{version}: "
                  f"{rec['status']} ({rec['total_seconds']:.1f}s)", file=sys.stderr)


if __name__ == "__main__":
    main()
