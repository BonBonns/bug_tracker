#!/usr/bin/env python3
"""Frontend entrypoint-coverage correction -- a standalone tool, separate from the frozen R01
producer (export_redos_npm_integ.sc) and separate from any R02 adapter/classifier work.

Real bug this fixes (see audit/REMAINING_SIX_NO_COMPLEXITY_CANDIDATE.md section 4 and
audit/R02_DECISION.md "A third, real finding this taxonomy has no slot for"): jssrc2cpg.sh has its
own default file/folder ignore rules (decompiled + synthetic-probe-confirmed in
audit/PREFILTER_DIVERGENCE_AUDIT.md), including a folder-name ignore list that contains "dist".
For a package whose package.json "main"/"module"/"exports" resolve into dist/ with NO parallel
src/ shipped in the tarball (multi-spec-parser@0.4.2 is the real, confirmed example), jssrc2cpg
silently drops 100% of that package's real code before a single CPG node for it is ever created.
The frozen producer then correctly reports zero sinks over the CPG it was handed -- but that is a
false "nothing to find," not a real negative, because the CPG itself never contained the package's
real, reachable source.

This tool runs BEFORE/ALONGSIDE the real jssrc2cpg.sh CPG build (never modifying it, never
touching export_redos_npm_integ.sc, redos_verdict.py, or any pipeline-wiring file) and:

  1. Parses package.json and resolves every distinct JS/TS entrypoint the package declares
     ("main", "module", "types"/"typings", every string leaf inside "exports", with a fallback to
     "./index.js" when no entrypoint field exists at all -- Node's own default resolution rule).
  2. Builds a real CPG with the real jssrc2cpg.sh and inspects it via a real Joern query
     (`cpg.file.name.l`, the same mechanism the REMAINING_SIX audit's "FILES IN CPG" listings used)
     to check whether every resolved entrypoint actually made it in.
  3. For any entrypoint missing because it falls under jssrc2cpg's own default ignore rules
     (folder-name list or filename-suffix regex -- the exact real constants from
     audit/PREFILTER_DIVERGENCE_AUDIT.md, re-confirmed here directly against the installed
     jssrc2cpg-4.0.608.jar), stages a corrected copy of the source tree with ONLY the specific
     ignored ancestor directory/file of that MISSING, RESOLVED entrypoint relocated to a
     non-ignored name, and rebuilds the CPG from the staged copy. This is entrypoint-identity
     driven: an ignored folder that is not any resolved entrypoint's own path is never touched
     (see the "src_plus_vendored_dist" fixture / the real "linux-device" package validation).
  4. Reports, per package: total real JS/TS source files in the raw extracted tarball, how many
     made it into the real (possibly corrected) CPG, and an itemized exclusion accounting (folder-
     ignore, suffix-ignore, node_modules, line-length) for every file that did not.
  5. Emits ENTRYPOINT_NOT_PRESENT_IN_CPG (with the specific path and reason) for any real,
     resolved entrypoint that still cannot be gotten into the CPG after the correction attempt --
     a status distinct from "genuinely scanned, zero sinks found," never silently merged into it.

Usage:
    python3 frontend_coverage_check.py --src-dir /path/to/extracted/source [--jssrc2cpg-only]
    python3 frontend_coverage_check.py --tarball-url https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz
    python3 frontend_coverage_check.py --tarball-url ... --run-frozen-producer   # also reruns the
        real, unmodified export_redos_npm_integ.sc against the corrected CPG, matching
        run_pilot25.py's own exact invocation pattern, and reports sink_targets/dangerous_sinks
        before vs. after.

Standalone: not wired into redos_verdict.py, provenance.py, staged_enablement.py, or any
aggregator. Its JSON output is meant for a *future* pipeline integration to consume.
"""
import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
FROZEN_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/"
                    "producers/export_redos_npm_integ.sc")

FETCH_TIMEOUT = 60
JSSRC2CPG_TIMEOUT = 300
JOERN_TIMEOUT = 300

JS_TS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# ===== jssrc2cpg's own real default ignore rules =====
# Source of truth: audit/PREFILTER_DIVERGENCE_AUDIT.md, itself built by decompiling
# jssrc2cpg-4.0.608.jar (io.joern.jssrc2cpg.utils.AstGenRunner$) and independently confirmed by
# synthetic-probe testing (a file placed inside each excluded shape verified dropped from a real
# CPG; a sibling file outside it verified kept). Re-confirmed directly again for this tool by
# decompiling the SAME installed jar (`javap -p -c ... AstGenRunner\$.class`, `strings`) under
# $JOERN_HOME/frontends/jssrc2cpg/lib/io.joern.jssrc2cpg-4.0.608.jar -- the folder-name list and
# filename-suffix regex byte-for-byte match what's documented there. These constants are
# reproduced here (not imported from prefilter_select_25.py) so this tool has no dependency on
# that file and stays genuinely standalone; the VALUES themselves are the exact real ones, not
# invented.
AST_GEN_DEFAULT_IGNORE_SUFFIX = re.compile(
    r"(conf|test|spec|[.-]min|\.d)\.(js|jsx|cjs|mjs|xsjs|xsjslib|ts|tsx)$")
AST_GEN_DEFAULT_IGNORE_FOLDERS = {
    "venv", "docs", "test", "tests", "e2e", "e2e-beta", "examples", "cypress", "jest-cache",
    "eslint-rules", "codemods", "flow-typed", "i18n", "vendor", "www", "dist", "build",
}
LINE_LENGTH_THRESHOLD = 10000  # jssrc2cpg's own real content-based minified-file cutoff


def classify_ignore_reason(relpath, abspath=None):
    """Returns one of: None (not ignored), 'NODE_MODULES', 'SUFFIX_IGNORE', 'FOLDER_IGNORE',
    'LINE_LENGTH_MINIFIED'. relpath uses '/' separators, relative to the jssrc2cpg input dir
    (i.e. it includes the leading 'package/' segment for a standard npm tarball layout)."""
    norm = relpath.replace(os.sep, "/")
    if "node_modules" in norm:  # jssrc2cpg's own real check is an UNANCHORED substring match
        return "NODE_MODULES"
    if AST_GEN_DEFAULT_IGNORE_SUFFIX.search(norm):
        return "SUFFIX_IGNORE"
    parts = norm.split("/")
    if any(p in AST_GEN_DEFAULT_IGNORE_FOLDERS for p in parts):
        return "FOLDER_IGNORE"
    if abspath is not None and os.path.isfile(abspath):
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if len(line) >= LINE_LENGTH_THRESHOLD:
                        return "LINE_LENGTH_MINIFIED"
        except OSError:
            pass
    return None


def ignored_folder_segment(relpath):
    """Returns the first (topmost) path segment of relpath that matches
    AST_GEN_DEFAULT_IGNORE_FOLDERS, or None."""
    for p in relpath.replace(os.sep, "/").split("/"):
        if p in AST_GEN_DEFAULT_IGNORE_FOLDERS:
            return p
    return None


# ===== Step 1: package.json entrypoint resolution =====

def _walk_exports_leaves(node, out):
    """Collects every string leaf inside a package.json 'exports' value, handling both a single
    string ('exports': './index.js') and a nested conditional-exports object/map shape
    ('exports': {'.': {'import': ..., 'require': ...}, './sub': '...'})."""
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _walk_exports_leaves(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_exports_leaves(v, out)


def resolve_entrypoints(package_json_doc):
    """Returns a sorted, de-duplicated list of distinct entrypoint paths (as declared, e.g.
    './dist/src/index.js') this package.json resolves to. Falls back to './index.js' -- Node's
    own default main-field resolution rule -- when no entrypoint field is present at all."""
    raw = []
    for key in ("main", "module", "types", "typings"):
        v = package_json_doc.get(key)
        if isinstance(v, str):
            raw.append(v)
    if "exports" in package_json_doc:
        _walk_exports_leaves(package_json_doc["exports"], raw)

    def _looks_like_js_ts(p):
        return any(p.endswith(ext) for ext in JS_TS_EXTS) or p.endswith(".d.ts") or p.endswith(".d.cts") or p.endswith(".d.mts")

    entrypoints = [p for p in raw if _looks_like_js_ts(p)]
    if not entrypoints:
        entrypoints = ["./index.js"]

    def _norm(p):
        p = p.strip()
        while p.startswith("./"):
            p = p[2:]
        return p.lstrip("/")

    seen = {}
    for p in entrypoints:
        seen[_norm(p)] = True
    return sorted(seen.keys())


# ===== Step 2: raw source inventory + CPG file listing =====

def iter_raw_js_ts_files(src_dir):
    """Every real JS/TS file under src_dir (no exclusions at all -- this IS the raw inventory the
    exclusion accounting is measured against), as (relpath-with-/-seps, abspath)."""
    out = []
    for root, _dirs, files in os.walk(src_dir):
        for fn in files:
            if fn.endswith(JS_TS_EXTS):
                abspath = os.path.join(root, fn)
                relpath = os.path.relpath(abspath, src_dir).replace(os.sep, "/")
                out.append((relpath, abspath))
    return sorted(out)


LIST_FILES_SCRIPT = os.path.join(HERE, "_fcc_list_cpg_files.sc")
_LIST_FILES_SCRIPT_BODY = (
    'import io.shiftleft.semanticcpg.language._\n'
    '@main def exec(cpgFile: String) = {\n'
    '  importCpg(cpgFile)\n'
    '  println("===FCC_FILES_BEGIN===")\n'
    '  cpg.file.name.l.sorted.foreach(f => println(s"FCC_FILE|$f"))\n'
    '  println("===FCC_FILES_END===")\n'
    '}\n'
)


def _ensure_list_files_script():
    # Written once, reused across runs. Verified against a real synthetic probe CPG (see
    # FRONTEND_COVERAGE_FIX.md) -- this is the same `cpg.file.name.l` mechanism the
    # REMAINING_SIX_NO_COMPLEXITY_CANDIDATE.md audit's own "FILES IN CPG" listings used
    # (matches its own scratch query3.sc pattern), not a guessed API.
    if not os.path.isfile(LIST_FILES_SCRIPT) or open(LIST_FILES_SCRIPT).read() != _LIST_FILES_SCRIPT_BODY:
        with open(LIST_FILES_SCRIPT, "w") as f:
            f.write(_LIST_FILES_SCRIPT_BODY)
    return LIST_FILES_SCRIPT


def build_cpg(src_dir, cpg_path):
    r = subprocess.run([f"{JOERN_HOME}/jssrc2cpg.sh", "-o", cpg_path, src_dir],
                        capture_output=True, text=True, timeout=JSSRC2CPG_TIMEOUT)
    ok = os.path.isfile(cpg_path)
    return ok, (r.stdout + r.stderr)


def list_cpg_files(cpg_path):
    script = _ensure_list_files_script()
    r = subprocess.run([f"{JOERN_HOME}/joern", "--script", script, "--param", f"cpgFile={cpg_path}"],
                        capture_output=True, text=True, timeout=JOERN_TIMEOUT)
    out = r.stdout + r.stderr
    files = []
    in_block = False
    for line in out.splitlines():
        if line.strip() == "===FCC_FILES_BEGIN===":
            in_block = True
            continue
        if line.strip() == "===FCC_FILES_END===":
            in_block = False
            continue
        if in_block and line.startswith("FCC_FILE|"):
            files.append(line[len("FCC_FILE|"):])
    return files, out


# ===== Step 3: entrypoint-identity-driven recovery staging =====

def stage_recovered_source(src_dir, missing_entrypoints):
    """missing_entrypoints: list of (relpath, reason) for entrypoints NOT present in the
    first-pass CPG, relpath relative to src_dir (posix seps), reason in
    {'FOLDER_IGNORE','SUFFIX_IGNORE','NODE_MODULES'}.

    Copies src_dir to a temp staged dir and, ONLY for the ignored ancestor directory/file that is
    part of one of these MISSING, package.json-RESOLVED entrypoints' own path, relocates it to a
    non-ignored name. Nothing else in the tree is touched -- an ignored folder that is not part of
    any missing resolved entrypoint's path is left exactly as-is (this is the discipline property
    item 6 requires; see the src_plus_vendored_dist fixture and the real linux-device validation).

    Returns (staged_dir, {original_relpath: recovered_relpath}).
    """
    staged_dir = tempfile.mkdtemp(prefix="fcc_staged_")
    shutil.copytree(src_dir, staged_dir, dirs_exist_ok=True)

    renamed_dirs = {}  # abs original dir -> abs new dir, so two entrypoints sharing one ignored
                        # ancestor (e.g. both "main" and "types" under the same dist/) only cause
                        # ONE rename, not a rename-of-an-already-renamed-path error.
    recovered_map = {}

    # Pass A: folder-level renames (FOLDER_IGNORE / NODE_MODULES) first. Doing these before any
    # SUFFIX_IGNORE copy matters: if an entrypoint's ignored ancestor directory gets renamed here,
    # a later suffix-copy for a DIFFERENT entrypoint under that same directory must operate on the
    # already-renamed path, not the stale original one (otherwise the stale copy gets silently
    # carried along inside the directory rename and the recorded recovered_relpath is wrong).
    dir_rename_relmap = {}  # orig ancestor dir relpath -> new ancestor dir relpath
    for relpath, reason in missing_entrypoints:
        if reason not in ("FOLDER_IGNORE", "NODE_MODULES"):
            continue
        parts = relpath.split("/")
        seg = ignored_folder_segment(relpath)
        if seg is not None:
            seg_index = parts.index(seg)
        else:
            # NODE_MODULES case (unanchored substring, not necessarily a whole path segment in
            # AST_GEN_DEFAULT_IGNORE_FOLDERS) -- relocate the first segment containing the
            # substring "node_modules".
            idx = next((i for i, p in enumerate(parts) if "node_modules" in p), None)
            if idx is None:
                continue
            seg, seg_index = parts[idx], idx
        orig_dir_rel = "/".join(parts[:seg_index + 1])
        if orig_dir_rel in dir_rename_relmap:
            new_dir_rel = dir_rename_relmap[orig_dir_rel]
        else:
            new_seg = f"_redos_included_{seg}"
            new_dir_rel = "/".join(parts[:seg_index] + [new_seg])
            orig_dir_abs = os.path.join(staged_dir, *orig_dir_rel.split("/"))
            new_dir_abs = os.path.join(staged_dir, *new_dir_rel.split("/"))
            if os.path.isdir(orig_dir_abs) and not os.path.exists(new_dir_abs):
                os.rename(orig_dir_abs, new_dir_abs)
            dir_rename_relmap[orig_dir_rel] = new_dir_rel
        new_parts = parts[:seg_index] + [f"_redos_included_{seg}"] + parts[seg_index + 1:]
        recovered_map[relpath] = "/".join(new_parts)

    def _apply_dir_renames(relpath):
        """Rewrites relpath's ancestor directory through dir_rename_relmap if any prefix of it
        was renamed in Pass A (longest-matching-prefix, since renames are never nested here)."""
        for orig_dir_rel, new_dir_rel in dir_rename_relmap.items():
            prefix = orig_dir_rel + "/"
            if relpath.startswith(prefix):
                return new_dir_rel + "/" + relpath[len(prefix):]
        return relpath

    # Pass B: SUFFIX_IGNORE copies, using the POST-rename current location of each file.
    for relpath, reason in missing_entrypoints:
        if reason != "SUFFIX_IGNORE":
            continue
        current_relpath = _apply_dir_renames(relpath)
        src_abs = os.path.join(staged_dir, *current_relpath.split("/"))
        if not os.path.isfile(src_abs):
            continue
        base, ext = os.path.splitext(current_relpath)
        new_relpath = f"{base}_redosinc{ext}"
        dst_abs = os.path.join(staged_dir, *new_relpath.split("/"))
        shutil.copyfile(src_abs, dst_abs)
        recovered_map[relpath] = new_relpath

    return staged_dir, recovered_map


# ===== Orchestration =====

def fetch_and_extract(tarball_url, dest_root):
    req = urllib.request.Request(tarball_url, headers={"User-Agent": "frontend-coverage-check/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        data = resp.read()
    src_dir = os.path.join(dest_root, "src")
    os.makedirs(src_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(src_dir)
    return src_dir


def find_package_json(src_dir):
    """Standard npm tarballs extract to src_dir/package/package.json; handle that layout, and
    fall back to a direct src_dir/package.json for a non-tarball source dir passed directly."""
    candidates = [
        os.path.join(src_dir, "package", "package.json"),
        os.path.join(src_dir, "package.json"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    # last resort: shallow search
    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d != "node_modules"]
        if "package.json" in files:
            return os.path.join(root, "package.json")
    return None


def run_frozen_producer(cpg_path, work_dir, src_label, raw_subdir="raw"):
    raw_dir = os.path.join(work_dir, raw_subdir)
    r = subprocess.run([f"{JOERN_HOME}/joern", "--script", FROZEN_PRODUCER,
                         "--param", f"cpgFile={cpg_path}",
                         "--param", f"rawDir={raw_dir}",
                         "--param", f"srcLabel={src_label}"],
                        capture_output=True, text=True, timeout=JOERN_TIMEOUT)
    summary_path = os.path.join(raw_dir, "redos_npm_summary.json")
    if os.path.isfile(summary_path):
        return json.load(open(summary_path)), r.stdout + r.stderr
    return None, r.stdout + r.stderr


def check_package(src_dir, package_json_path=None, run_producer=False, src_label="pkg",
                   keep_staged=False):
    """Core entrypoint of this tool. src_dir is the directory PASSED TO jssrc2cpg.sh (i.e. the
    directory that CONTAINS the extracted 'package/' tree for a standard npm tarball, or any
    directory jssrc2cpg would be pointed at directly). Returns the full result dict."""
    t0 = time.time()
    result = {"src_dir": src_dir}

    pkg_json_path = package_json_path or find_package_json(src_dir)
    if pkg_json_path is None:
        result["status"] = "NO_PACKAGE_JSON"
        return result
    result["package_json_path"] = pkg_json_path
    pkg_root = os.path.dirname(pkg_json_path)  # e.g. .../src/package
    pkg_root_rel = os.path.relpath(pkg_root, src_dir).replace(os.sep, "/")
    if pkg_root_rel == ".":
        pkg_root_rel = ""

    with open(pkg_json_path) as f:
        pkg_doc = json.load(f)
    entrypoints = resolve_entrypoints(pkg_doc)
    result["package_name"] = pkg_doc.get("name")
    result["package_version"] = pkg_doc.get("version")
    result["resolved_entrypoints_declared"] = entrypoints

    # entrypoint path relative to src_dir (the jssrc2cpg input dir), matching how cpg.file.name
    # reports paths (confirmed directly against a real probe CPG -- see FRONTEND_COVERAGE_FIX.md)
    def to_src_dir_rel(ep):
        return (pkg_root_rel + "/" + ep) if pkg_root_rel else ep

    entry_relpaths = {ep: to_src_dir_rel(ep) for ep in entrypoints}

    # ----- raw inventory + static exclusion accounting -----
    raw_files = iter_raw_js_ts_files(src_dir)
    result["n_raw_js_ts_files"] = len(raw_files)
    exclusion_counts = {"NODE_MODULES": 0, "SUFFIX_IGNORE": 0, "FOLDER_IGNORE": 0,
                         "LINE_LENGTH_MINIFIED": 0}
    excluded_examples = {k: [] for k in exclusion_counts}
    for relpath, abspath in raw_files:
        reason = classify_ignore_reason(relpath, abspath)
        if reason:
            exclusion_counts[reason] += 1
            if len(excluded_examples[reason]) < 10:
                excluded_examples[reason].append(relpath)
    result["static_exclusion_accounting"] = {
        "counts": exclusion_counts,
        "examples_per_reason": excluded_examples,
        "n_statically_would_be_ignored": sum(exclusion_counts.values()),
        "n_statically_would_be_kept": len(raw_files) - sum(exclusion_counts.values()),
    }

    # ----- first-pass real CPG build -----
    work_dir = tempfile.mkdtemp(prefix="fcc_work_")
    staged_dir = None
    try:
        cpg1 = os.path.join(work_dir, "pass1.cpg.bin")
        ok1, log1 = build_cpg(src_dir, cpg1)
        if not ok1:
            result["status"] = "CPG_BUILD_FAILED"
            result["error"] = log1[-2000:]
            return result
        cpg1_files, _joern_log1 = list_cpg_files(cpg1)
        cpg1_files_set = set(cpg1_files)
        result["n_files_in_first_pass_cpg"] = len(cpg1_files)

        # ----- per-entrypoint coverage against the first-pass CPG -----
        missing = []
        coverage = {}
        for ep, relpath in entry_relpaths.items():
            present = relpath in cpg1_files_set
            abspath = os.path.join(src_dir, *relpath.split("/"))
            reason = None if present else classify_ignore_reason(relpath, abspath)
            exists_on_disk = os.path.isfile(abspath)
            coverage[ep] = {
                "relpath_in_cpg_namespace": relpath,
                "exists_on_disk": exists_on_disk,
                "present_in_first_pass_cpg": present,
                "ignore_reason_if_missing": reason,
            }
            if not present and exists_on_disk and reason:
                missing.append((relpath, reason))
        result["entrypoint_coverage_first_pass"] = coverage

        if not missing:
            result["status"] = "OK_ALL_ENTRYPOINTS_COVERED"
            result["correction_applied"] = False
            final_cpg = cpg1
        else:
            # ----- correction attempt: entrypoint-identity-driven staging, never a blanket
            # un-ignore (see stage_recovered_source's own docstring for the discipline property).
            staged_dir, recovered_map = stage_recovered_source(src_dir, missing)
            result["correction_applied"] = True
            result["staged_dir"] = staged_dir if keep_staged else None
            result["recovered_path_map"] = recovered_map
            cpg2 = os.path.join(work_dir, "pass2.cpg.bin")
            ok2, log2 = build_cpg(staged_dir, cpg2)
            if not ok2:
                result["status"] = "CORRECTED_CPG_BUILD_FAILED"
                result["error"] = log2[-2000:]
                return result
            cpg2_files, _joern_log2 = list_cpg_files(cpg2)
            cpg2_files_set = set(cpg2_files)
            result["n_files_in_corrected_cpg"] = len(cpg2_files)

            still_missing = []
            for relpath, reason in missing:
                recovered_relpath = recovered_map.get(relpath)
                recovered_present = recovered_relpath is not None and recovered_relpath in cpg2_files_set
                coverage_entry = next(c for ep, c in coverage.items()
                                       if c["relpath_in_cpg_namespace"] == relpath)
                coverage_entry["recovered_relpath"] = recovered_relpath
                coverage_entry["present_in_corrected_cpg"] = recovered_present
                if not recovered_present:
                    still_missing.append({"entrypoint_relpath": relpath, "reason": reason,
                                           "attempted_recovered_relpath": recovered_relpath})

            if still_missing:
                result["status"] = "ENTRYPOINT_NOT_PRESENT_IN_CPG"
                result["entrypoint_not_present"] = still_missing
            else:
                result["status"] = "OK_RECOVERED_ALL_ENTRYPOINTS"
            final_cpg = cpg2

        if run_producer:
            if result.get("correction_applied"):
                # Report BOTH: the real baseline (frozen producer against the UNCORRECTED
                # first-pass CPG -- what the pipeline gets today) and the real after-fix result,
                # so a reviewer can see the exact before/after counts side by side, per the
                # task's own required validation.
                before_summary, before_plog = run_frozen_producer(
                    cpg1, work_dir, src_label + "_before", raw_subdir="raw_before")
                result["frozen_producer_summary_before_fix"] = before_summary
                if before_summary is None:
                    result["frozen_producer_log_tail_before_fix"] = before_plog[-2000:]
            summary, plog = run_frozen_producer(final_cpg, work_dir, src_label)
            result["frozen_producer_summary"] = summary
            if result.get("correction_applied"):
                result["frozen_producer_summary_after_fix"] = summary
            if summary is None:
                result["frozen_producer_log_tail"] = plog[-2000:]

        result["elapsed_seconds"] = round(time.time() - t0, 1)
        return result
    finally:
        if not keep_staged:
            shutil.rmtree(work_dir, ignore_errors=True)
            if staged_dir and os.path.isdir(staged_dir):
                shutil.rmtree(staged_dir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src-dir", help="Directory to pass to jssrc2cpg.sh directly (already-extracted source).")
    ap.add_argument("--tarball-url", help="npm tarball URL to fetch and extract fresh.")
    ap.add_argument("--run-frozen-producer", action="store_true",
                     help="Also rerun the real, unmodified export_redos_npm_integ.sc against the "
                          "(possibly corrected) CPG, matching run_pilot25.py's own invocation.")
    ap.add_argument("--src-label", default="frontend-coverage-check", help="srcLabel passed to the producer.")
    ap.add_argument("--out", help="Write full JSON result to this path (also printed to stdout).")
    ap.add_argument("--keep-staged", action="store_true", help="Don't delete the staged/corrected source tree.")
    args = ap.parse_args()

    if not args.src_dir and not args.tarball_url:
        ap.error("one of --src-dir or --tarball-url is required")

    cleanup_dir = None
    try:
        if args.tarball_url:
            cleanup_dir = tempfile.mkdtemp(prefix="fcc_fetch_")
            src_dir = fetch_and_extract(args.tarball_url, cleanup_dir)
        else:
            src_dir = args.src_dir

        result = check_package(src_dir, run_producer=args.run_frozen_producer,
                                src_label=args.src_label, keep_staged=args.keep_staged)
    finally:
        if cleanup_dir and not args.keep_staged:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)


if __name__ == "__main__":
    main()
