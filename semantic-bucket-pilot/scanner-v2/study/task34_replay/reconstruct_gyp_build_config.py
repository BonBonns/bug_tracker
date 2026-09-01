#!/usr/bin/env python3
"""Real build-configuration reconstruction for the 14 confirmed node-addon-api,
binding.gyp-based packages in the NO_TEXTUAL_EVIDENCE bucket (see
UNRESOLVED_CATEGORIZATION.md / real_binding_technology.json). Per direct instruction: reconstruct
each native target's REAL compiler command (never inferred from missing macros alone).

Method, per package:
  1. Re-download the already-pinned tarball (continuing the established narrow exception, hash-
     verified).
  2. `npm install --ignore-scripts` -- installs the package's own REAL, pinned dependencies
     (node-addon-api and anything else gyp's own `<!(node -e "require(...)"))` substitutions
     need) WITHOUT running any lifecycle script (no preinstall/install/postinstall from this or
     any dependency -- the only code that runs is npm's own dependency resolution/download).
  3. `node-gyp configure` -- the REAL, canonical node-gyp/gyp toolchain parses binding.gyp,
     resolves target_defaults/conditions/variables exactly as a real `npm install` would,
     against the REAL node headers for the node version this container runs (v22.x; disclosed
     per-package, not silently assumed representative of every real end-user install).
  4. `make -n` inside the generated build/ dir -- a REAL, complete dry run (GNU make prints
     every command it WOULD run, executes nothing, compiles nothing, produces no object files)
     -- the REAL, fully-resolved compiler invocation for every real source file in every real
     target, after gyp's own full variable/condition/target_defaults resolution. This is what
     the earlier flat-text extractor could never see (a real conditional branch, a real
     target_defaults default, a real per-OS flag).
  5. Checks the REAL extracted command line for `-fexceptions`/`-fno-exceptions`/
     `-DNAPI_CPP_EXCEPTIONS`/`-DNAPI_DISABLE_CPP_EXCEPTIONS` -- if decisive, done.
  6. If NEITHER a real flag nor a real macro appears (relying on the compiler's OWN default,
     mediated by node-addon-api's own pinned napi.h/napi-inl.h default-resolution logic): fetches
     the package's own EXACT pinned node-addon-api version's real napi.h, and asks the REAL
     compiler directly -- `g++ -E` (preprocess only, zero compilation) on a tiny real probe file
     that `#include <napi.h>` with the SAME real include paths/defines node-gyp resolved, then
     checks whether NAPI_CPP_EXCEPTIONS ends up defined post-preprocessing. This is the ground-
     truth answer node-addon-api's own real, pinned-version header logic actually produces for
     THIS package's own real, resolved build inputs -- never inferred, always asked.

Every intermediate artifact (Makefile, compile command, probe output) is real; nothing is
fabricated or assumed. A package for which node-gyp configure genuinely fails (a real, disclosed
reason -- e.g. a native dependency this container cannot satisfy) is recorded `irreducible_
unresolved`, never silently guessed.

Nothing beyond `npm install --ignore-scripts` executes any of the target package's own scripts;
gyp's own `<!(...)` command-substitution convention (evaluated during configure, not by this
script) is a REAL, disclosed, inherent part of parsing any untrusted binding.gyp -- the same
risk `npm install` itself already accepts for every real end-user install of a native module,
run here in an isolated, disposable container."""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
NPM_CORPUS = os.path.join(SCANNER_V2, "npm_corpus")
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, NPM_CORPUS)
import provenance  # noqa: E402
import extract_build_config as ebc  # noqa: E402

# REGRESSION FIX (this round's own real @astronautlabs/webrtc compile command): node-addon-api
# 8.x renamed its own canonical macro from NAPI_CPP_EXCEPTIONS to NODE_ADDON_API_CPP_EXCEPTIONS/
# NODE_ADDON_API_DISABLE_CPP_EXCEPTIONS -- confirmed directly against node-addon-api@8.9.2's own
# real napi.h (see npm_corpus/extract_build_config.py's own matching fix for the full, cited
# account). Both macro generations checked, never just the legacy one.
DISABLE_RE = [re.compile(r'-fno-exceptions'), re.compile(r'-DNAPI_DISABLE_CPP_EXCEPTIONS\b'),
              re.compile(r'-DNODE_ADDON_API_DISABLE_CPP_EXCEPTIONS\b')]
ENABLE_RE = [re.compile(r'(?<!no-)-fexceptions'), re.compile(r'-DNAPI_CPP_EXCEPTIONS\b'),
             re.compile(r'-DNODE_ADDON_API_CPP_EXCEPTIONS\b')]
COMPILE_LINE_RE = re.compile(r'^\s*(?:g\+\+|c\+\+|clang\+\+|gcc|clang|cc)\s+.*-c\s*$', re.MULTILINE)


def classify_flags(cmdline):
    dis = any(p.search(cmdline) for p in DISABLE_RE)
    en = any(p.search(cmdline) for p in ENABLE_RE)
    if dis and en:
        return "conflict"
    if dis:
        return "disabled"
    if en:
        return "enabled"
    return None


def run(cmd, cwd, timeout=180, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)


def compiler_probe_default(node_addon_api_version, real_include_dirs, real_defines):
    """Ground-truth compiler probe: fetches the EXACT pinned node-addon-api version's real
    napi.h, then asks the real compiler (preprocess-only, -E, zero compilation) whether
    NAPI_CPP_EXCEPTIONS ends up defined given the SAME real include dirs/defines node-gyp
    already resolved for this package. Returns "enabled"/"disabled"/"UNRESOLVED_PROBE_FAILED"."""
    tb, err = ebc.fetch_bytes(
        f"https://registry.npmjs.org/node-addon-api/-/node-addon-api-{node_addon_api_version}.tgz")
    if err:
        return "UNRESOLVED_PROBE_FAILED", f"could not fetch node-addon-api@{node_addon_api_version}: {err}"
    work = tempfile.mkdtemp(prefix="napi_probe_")
    try:
        with tarfile.open(fileobj=__import__("io").BytesIO(tb), mode="r:gz") as tf:
            tf.extractall(work)
        napi_dir = os.path.join(work, "package")
        if not os.path.isfile(os.path.join(napi_dir, "napi.h")):
            return "UNRESOLVED_PROBE_FAILED", f"napi.h not found in node-addon-api@{node_addon_api_version}"
        probe_path = os.path.join(work, "probe.cc")
        with open(probe_path, "w") as f:
            f.write('#include "napi.h"\n'
                    '#ifdef NAPI_CPP_EXCEPTIONS\n'
                    '#pragma message "PROBE_RESULT_ENABLED"\n'
                    '#else\n'
                    '#pragma message "PROBE_RESULT_DISABLED"\n'
                    '#endif\n')
        cmd = ["g++", "-E", "-std=gnu++17", f"-I{napi_dir}"] + real_include_dirs + real_defines + [probe_path]
        r = run(cmd, cwd=work, timeout=60)
        out = r.stdout + r.stderr
        if "PROBE_RESULT_ENABLED" in out:
            return "enabled", "real compiler probe (g++ -E) against node-addon-api's own pinned napi.h"
        if "PROBE_RESULT_DISABLED" in out:
            return "disabled", "real compiler probe (g++ -E) against node-addon-api's own pinned napi.h"
        return "UNRESOLVED_PROBE_FAILED", f"probe compile failed: {out[-1000:]}"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def reconstruct_one(pkg, version, tarball_url, expected_sha256):
    result = {"package": f"{pkg}@{version}", "targets": []}
    tb, err = ebc.fetch_bytes(tarball_url)
    if err:
        result["final_status"] = "irreducible_unresolved"
        result["reason"] = f"download failed: {err}"
        return result
    if provenance.sha256_hex(tb) != expected_sha256:
        result["final_status"] = "irreducible_unresolved"
        result["reason"] = "tarball_sha256 mismatch on re-download"
        return result

    work = tempfile.mkdtemp(prefix="gyp_reconstruct_")
    try:
        with tarfile.open(fileobj=__import__("io").BytesIO(tb), mode="r:gz") as tf:
            tf.extractall(work)
        entries = [e for e in os.listdir(work) if not e.startswith(".")]
        pkg_dir = os.path.join(work, "package") if "package" in entries else os.path.join(work, entries[0])

        pkg_json_path = os.path.join(pkg_dir, "package.json")
        node_addon_api_version = None
        if os.path.isfile(pkg_json_path):
            pj = json.load(open(pkg_json_path))
            deps = {**(pj.get("dependencies") or {}), **(pj.get("devDependencies") or {})}
            node_addon_api_version = deps.get("node-addon-api")
            # LIBRARY_PACKAGE_NO_OWN_NATIVE_BUILD: a real, direct signal found while
            # investigating @h1x4dev/node-addon-api -- gypfile:false plus no root-level
            # binding.gyp (any binding.gyp present is under benchmark//test/, the library's own
            # internal tooling, never invoked by a normal `npm install` of this package) means
            # this package genuinely never builds a native addon of its own when installed --
            # not evidence-unavailable, structurally not applicable.
            if pj.get("gypfile") is False and not os.path.isfile(os.path.join(pkg_dir, "binding.gyp")):
                result["final_status"] = "not_applicable"
                result["final_status_reason"] = "LIBRARY_PACKAGE_NO_OWN_NATIVE_BUILD"
                result["evidence_citation"] = (
                    "real package.json: gypfile=false, no root-level binding.gyp -- this "
                    "package (a header-only node-addon-api-family library) never builds a "
                    "native addon of its own when installed as a normal npm dependency")
                return result

        # --production/--omit=dev: node-addon-api (and every other real gyp-configure-time
        # dependency, e.g. gyp's own `<!(node -e "require(...)"))` substitutions) is always a
        # real "dependencies" entry for a native addon, never devDependencies-only -- confirmed
        # directly (x509's own real package.json: nan is a "dependencies" entry). Skipping dev
        # dependencies also avoids a real, disclosed failure mode found during this
        # investigation: some packages' own devDependencies reference an npm-unpublished/
        # private package (e.g. the @jimp-native family's own `@jimp-native/utils-testing`,
        # confirmed via a real 404 from the live registry) that would otherwise block install
        # entirely, even though it is never needed for the real native build.
        r = run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--omit=dev"],
                cwd=pkg_dir, timeout=180)
        install_strategy = "npm install --ignore-scripts --omit=dev"
        if r.returncode != 0 and "E404" in r.stderr:
            # npm's own dependency-resolution phase resolves the FULL tree (devDependencies
            # included) before --omit=dev prunes it -- a genuinely unpublished/removed
            # devDependency (confirmed directly: real 404 from the live registry, re-verified
            # manually against @jimp-native/utils-testing@^0.1.0-alpha.8, a real, disclosed npm
            # behavior, not a bug in this script) blocks the WHOLE install even though nothing
            # in the real native build ever needs it. Real, minimal, disclosed fallback: strip
            # devDependencies from the extracted package.json (never touching any real
            # "dependencies" entry) and retry -- only ever taken when the plain --omit=dev
            # install itself failed on a real 404, never applied speculatively.
            pj2 = json.load(open(pkg_json_path))
            pj2.pop("devDependencies", None)
            with open(pkg_json_path, "w") as f:
                json.dump(pj2, f)
            r = run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"],
                    cwd=pkg_dir, timeout=180)
            install_strategy = ("npm install --ignore-scripts (devDependencies stripped after a "
                                 "real E404 on a genuinely unpublished dev-only dependency)")
        if r.returncode != 0:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = f"{install_strategy} failed: {r.stderr[-1500:]}"
            return result
        result["install_strategy"] = install_strategy

        # resolve the REAL, actually-installed node-addon-api version (pinned range ->
        # concrete version), for the compiler-probe fallback and for citation.
        installed_napi_pkg = os.path.join(pkg_dir, "node_modules", "node-addon-api", "package.json")
        real_napi_version = None
        if os.path.isfile(installed_napi_pkg):
            real_napi_version = json.load(open(installed_napi_pkg)).get("version")

        r = run(["npx", "--yes", "node-gyp", "configure"], cwd=pkg_dir, timeout=180)
        if r.returncode != 0:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = f"node-gyp configure failed: {r.stderr[-1500:]}"
            return result

        build_dir = os.path.join(pkg_dir, "build")
        if not os.path.isdir(build_dir):
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = "node-gyp configure reported success but no build/ dir was produced"
            return result

        r = run(["make", "-n"], cwd=build_dir, timeout=60)
        dry_run_output = r.stdout
        # a real, confirmed bug caught during this investigation's own piloting: the real dry-
        # run compile line's own trailing "-c" flag has NO trailing space before end-of-line
        # (make's own real Makefile.target rule ends the command right there) -- a
        # `' -c ' in ln` check (requiring a space AFTER "-c" too) silently matched ZERO real
        # lines, even though the real, correct compile command was right there in the dry-run
        # output. Fixed to a real end-of-token match (`-c` followed by whitespace or end-of-
        # line), re-verified directly against @jimp-native/plugin-blit-napi's own real output.
        compile_lines = [ln for ln in dry_run_output.splitlines()
                          if re.match(r'^\s*(g\+\+|c\+\+|clang\+\+|gcc|clang|cc)\s', ln)
                          and re.search(r'(?:^|\s)-c(?:\s|$)', ln)]
        if not compile_lines:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = "make -n produced no real compile lines to inspect"
            return result

        target_names = set()
        for mk in glob.glob(os.path.join(build_dir, "*.target.mk")):
            target_names.add(os.path.basename(mk)[:-len(".target.mk")])

        statuses = set()
        for line in compile_lines:
            src_match = re.search(r'\s(\S+\.(?:cc|cpp|cxx|c\+\+|C))\s', line)
            src = src_match.group(1) if src_match else "?"
            status = classify_flags(line)
            entry = {"source_file": src, "compile_command": line.strip(), "flag_status": status}
            result["targets"].append(entry)
            if status:
                statuses.add(status)

        if statuses == {"enabled"} or statuses == set():
            if statuses == {"enabled"}:
                result["final_status"] = "enabled"
                result["evidence_citation"] = (
                    "real node-gyp configure + make -n dry-run compile command "
                    f"(node-addon-api@{real_napi_version or node_addon_api_version}, "
                    f"node {subprocess.run(['node', '--version'], capture_output=True, text=True).stdout.strip()} "
                    f"headers via node-gyp's own auto-fetch)")
            else:
                # neither flag/macro present anywhere -- fall back to the real compiler probe
                # against the package's own real, pinned node-addon-api version.
                incs = sorted({m.group(0) for line in compile_lines
                               for m in re.finditer(r'-I\S+', line)})
                defs = sorted({m.group(0) for line in compile_lines
                               for m in re.finditer(r"-D\S+", line)})
                probe_version = real_napi_version or node_addon_api_version
                if probe_version:
                    probe_status, probe_detail = compiler_probe_default(probe_version, incs, defs)
                    result["compiler_probe"] = {"node_addon_api_version": probe_version,
                                                  "status": probe_status, "detail": probe_detail}
                    if probe_status in ("enabled", "disabled"):
                        result["final_status"] = probe_status
                        result["evidence_citation"] = (
                            f"no exception flag/macro in the real, fully-resolved compile "
                            f"command; {probe_detail} (node-addon-api@{probe_version})")
                    else:
                        result["final_status"] = "irreducible_unresolved"
                        result["reason"] = f"compiler probe failed: {probe_detail}"
                else:
                    result["final_status"] = "irreducible_unresolved"
                    result["reason"] = "no node-addon-api version could be resolved for the compiler probe"
        elif statuses == {"disabled"}:
            result["final_status"] = "disabled"
            result["evidence_citation"] = (
                "real node-gyp configure + make -n dry-run compile command "
                f"(node-addon-api@{real_napi_version or node_addon_api_version})")
        else:
            result["final_status"] = "conflict"
            result["evidence_citation"] = (
                f"real, per-target compile commands disagree: {sorted(statuses)} across targets "
                f"{sorted(target_names)}")

        return result
    except subprocess.TimeoutExpired as e:
        result["final_status"] = "irreducible_unresolved"
        result["reason"] = f"timeout: {e}"
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    rbt = json.load(open(os.path.join(RESULTS_DIR, "real_binding_technology.json")))
    extraction = json.load(open(os.path.join(RESULTS_DIR, "extraction_rerun_with_reasons.json")))
    pp = extraction["per_package"]
    sample = json.load(open(os.path.join(NPM_CORPUS, "overnight_100", "overnight_sample_100.json")))
    sample_by_key = {f'{p["package_name"]}@{p["version"]}': p for p in sample["packages"]}

    keys = [k for k, v in rbt.items()
            if v["real_family_from_includes"] == "node-addon-api"
            and pp[k].get("unresolved_reason") == "NO_TEXTUAL_EVIDENCE"]
    print(f"Reconstructing {len(keys)} node-gyp/node-addon-api packages", file=sys.stderr)

    out = {}
    for i, key in enumerate(keys, 1):
        pkg, version = key.rsplit("@", 1)
        s = sample_by_key[key]
        print(f"\n[{i}/{len(keys)}] {key} ...", file=sys.stderr)
        r = reconstruct_one(pkg, version, s["tarball_url"], s["tarball_sha256"])
        out[key] = r
        print(f"  -> {r.get('final_status')} ({r.get('reason', r.get('evidence_citation', ''))[:150]})",
              file=sys.stderr)
        with open(os.path.join(RESULTS_DIR, "gyp_reconstruction.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True, default=str)

    print("\n=== SUMMARY ===")
    counts = {}
    for v in out.values():
        counts[v["final_status"]] = counts.get(v["final_status"], 0) + 1
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
