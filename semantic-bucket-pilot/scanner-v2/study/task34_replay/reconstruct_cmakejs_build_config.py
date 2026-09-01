#!/usr/bin/env python3
"""Real build-configuration reconstruction for the 8 confirmed node-addon-api, cmake-js-based
packages (CMAKE_JS_EXTERNAL_DEFAULT bucket). Per direct instruction: use the package's own
pinned cmake-js version and arguments, in an isolated, network-disabled environment; configure
only, never build/execute the addon; capture the real generated compile commands.

Method, per package:
  1. Re-download the already-pinned tarball (continuing the established narrow exception, hash-
     verified).
  2. `npm install --ignore-scripts [--omit=dev]` -- installs the package's own real, pinned
     `dependencies` (node-addon-api, etc.), same discipline as the gyp reconstruction script
     (falls back to stripping a genuinely-unpublished devDependency on a real E404, never
     touching a real "dependencies" entry -- see that script's own docstring for the real,
     confirmed case this handles).
  3. `npm install cmake-js@<the package's OWN real pinned devDependency version> --no-save
     --ignore-scripts` -- installs ONLY cmake-js itself, at the exact version this package
     declares, without touching any of the package's OTHER devDependencies.
  4. ONE-TIME, SHARED, network-ALLOWED priming of cmake-js's own well-known Node.js
     distribution-headers cache (`~/.cmake-js/node-<arch>/v<node-version>`) -- a fixed, trusted,
     versioned download from nodejs.org, the same kind of operation node-gyp's own `configure`
     already performs for every other reconstruction in this investigation; this is NOT the
     package's own untrusted configure logic running, so it is not isolated.
  5. THE PACKAGE'S OWN `cmake-js configure` invocation (which DOES execute the package's own,
     untrusted CMakeLists.txt -- real `execute_process()`/custom logic) is wrapped in
     `unshare --net --map-root-user`, a real, verified, working network-namespace isolation
     (confirmed directly during this investigation's own setup: DNS resolution and all outbound
     connections fail inside it) -- reusing the already-primed cache from step 4, so the real
     configure step itself never touches the network. `--CDCMAKE_EXPORT_COMPILE_COMMANDS=ON` is
     passed so CMake emits a real `compile_commands.json` -- configuration only, no `cmake-js
     build`/`cmake --build`, so nothing is ever actually compiled or linked.
  6. Reads the REAL `build/compile_commands.json` this produced -- the fully-resolved compiler
     invocation CMake itself generated for every real source file.
  7. Checks for `-fexceptions`/`-fno-exceptions`/`-DNAPI_CPP_EXCEPTIONS`/
     `-DNAPI_DISABLE_CPP_EXCEPTIONS`; if genuinely absent (a REAL, disclosed finding of this
     investigation, distinct from what was assumed in the earlier UNRESOLVED_CATEGORIZATION.md
     writeup: cmake-js/CMake does NOT apply node-gyp/common.gypi's own `-fno-exceptions`
     default -- it simply leaves the compiler's OWN default in place, confirmed directly against
     @eliyya/sange's own real compile_commands.json, which carries neither flag at all), falls
     back to the SAME real compiler probe (`g++ -E`, zero compilation) against the package's own
     pinned node-addon-api version, using the SAME real, resolved include paths CMake itself
     produced."""
import glob
import json
import os
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
sys.path.insert(0, HERE)
import provenance  # noqa: E402
import extract_build_config as ebc  # noqa: E402
from reconstruct_gyp_build_config import classify_flags, compiler_probe_default, run  # noqa: E402


def prime_cmakejs_cache(pkg_dir_with_cmakejs):
    """One-time, network-ALLOWED priming of cmake-js's own well-known node-headers cache, via
    a package that already has cmake-js installed. Real, trusted, versioned download -- never
    the package's own untrusted configure logic (that always runs isolated, separately, per
    package, in reconstruct_one())."""
    r = run(["node_modules/.bin/cmake-js", "install"], cwd=pkg_dir_with_cmakejs, timeout=120)
    return r.returncode == 0 or "already" in (r.stdout + r.stderr).lower()


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

    work = tempfile.mkdtemp(prefix="cmakejs_reconstruct_")
    try:
        with tarfile.open(fileobj=__import__("io").BytesIO(tb), mode="r:gz") as tf:
            tf.extractall(work)
        entries = [e for e in os.listdir(work) if not e.startswith(".")]
        pkg_dir = os.path.join(work, "package") if "package" in entries else os.path.join(work, entries[0])

        pkg_json_path = os.path.join(pkg_dir, "package.json")
        pj = json.load(open(pkg_json_path))
        deps = {**(pj.get("dependencies") or {}), **(pj.get("devDependencies") or {})}
        node_addon_api_version = deps.get("node-addon-api")
        cmake_js_version = deps.get("cmake-js")
        if not cmake_js_version:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = "no cmake-js version pinned in this package's own package.json"
            return result

        r = run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--omit=dev"],
                cwd=pkg_dir, timeout=180)
        if r.returncode != 0 and "E404" in r.stderr:
            pj2 = json.load(open(pkg_json_path))
            pj2.pop("devDependencies", None)
            with open(pkg_json_path, "w") as f:
                json.dump(pj2, f)
            r = run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"],
                    cwd=pkg_dir, timeout=180)
        if r.returncode != 0:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = f"npm install (production deps) failed: {r.stderr[-1500:]}"
            return result
        # ALWAYS prefer the real, concrete, actually-installed version over the package.json's
        # own raw semver RANGE string (e.g. "^8.9.0") -- a real bug caught during this
        # investigation's own run (@astronautlabs/webrtc: passing "^8.9.0" straight to the
        # tarball-fetch URL 404s, since npm's own registry has no literal version "^8.9.0").
        installed = os.path.join(pkg_dir, "node_modules", "node-addon-api", "package.json")
        if os.path.isfile(installed):
            node_addon_api_version = json.load(open(installed)).get("version") or node_addon_api_version

        r = run(["npm", "install", f"cmake-js@{cmake_js_version}", "--no-save",
                 "--ignore-scripts", "--no-audit", "--no-fund"], cwd=pkg_dir, timeout=120)
        if r.returncode != 0:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = f"npm install cmake-js@{cmake_js_version} failed: {r.stderr[-1000:]}"
            return result

        if not prime_cmakejs_cache(pkg_dir):
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = "cmake-js's own node-headers cache priming failed"
            return result

        napi_include_dir = None
        napi_pkg = os.path.join(pkg_dir, "node_modules", "node-addon-api", "package.json")
        if os.path.isfile(napi_pkg):
            napi_include_dir = os.path.join(pkg_dir, "node_modules", "node-addon-api")

        configure_cmd = ("./node_modules/.bin/cmake-js configure "
                          "--CDCMAKE_EXPORT_COMPILE_COMMANDS=ON")
        if napi_include_dir:
            configure_cmd += f" --CDNODE_ADDON_INC={napi_include_dir}"
        r = run(["unshare", "--net", "--map-root-user", "bash", "-c", configure_cmd],
                cwd=pkg_dir, timeout=120)
        if r.returncode != 0:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = f"cmake-js configure (network-isolated) failed: {(r.stdout + r.stderr)[-1500:]}"
            return result

        cc_path = os.path.join(pkg_dir, "build", "compile_commands.json")
        if not os.path.isfile(cc_path):
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = "cmake-js configure succeeded but no compile_commands.json was produced"
            return result

        compile_commands = json.load(open(cc_path))
        if not compile_commands:
            result["final_status"] = "irreducible_unresolved"
            result["reason"] = "compile_commands.json is empty -- no real compile command to inspect"
            return result

        statuses = set()
        for entry in compile_commands:
            cmdline = entry.get("command", "")
            status = classify_flags(cmdline)
            result["targets"].append({"source_file": entry.get("file"),
                                        "compile_command": cmdline, "flag_status": status})
            if status:
                statuses.add(status)

        if statuses == {"enabled"}:
            result["final_status"] = "enabled"
            result["evidence_citation"] = (
                f"real cmake-js@{cmake_js_version} configure + real compile_commands.json "
                f"(node-addon-api@{node_addon_api_version})")
        elif statuses == {"disabled"}:
            result["final_status"] = "disabled"
            result["evidence_citation"] = (
                f"real cmake-js@{cmake_js_version} configure + real compile_commands.json "
                f"(node-addon-api@{node_addon_api_version})")
        elif len(statuses) > 1:
            result["final_status"] = "conflict"
            result["evidence_citation"] = f"real, per-target compile commands disagree: {sorted(statuses)}"
        else:
            # neither flag/macro present anywhere -- REAL, DISCLOSED finding of this
            # investigation: cmake-js/CMake does not apply node-gyp's own -fno-exceptions
            # default, so the compiler's OWN default governs; fall back to the real compiler
            # probe against this package's own pinned node-addon-api version.
            incs = sorted({f"-I{seg}" for entry in compile_commands
                           for seg in entry.get("command", "").split()
                           if seg.startswith("-I")})
            incs = sorted({seg for entry in compile_commands
                           for seg in entry.get("command", "").split() if seg.startswith("-I")})
            defs = sorted({seg for entry in compile_commands
                           for seg in entry.get("command", "").split() if seg.startswith("-D")})
            if node_addon_api_version:
                probe_status, probe_detail = compiler_probe_default(node_addon_api_version, incs, defs)
                result["compiler_probe"] = {"node_addon_api_version": node_addon_api_version,
                                              "status": probe_status, "detail": probe_detail}
                if probe_status in ("enabled", "disabled"):
                    result["final_status"] = probe_status
                    result["evidence_citation"] = (
                        f"no exception flag/macro in the real, fully-resolved cmake-js compile "
                        f"command; {probe_detail} (node-addon-api@{node_addon_api_version})")
                else:
                    result["final_status"] = "irreducible_unresolved"
                    result["reason"] = f"compiler probe failed: {probe_detail}"
            else:
                result["final_status"] = "irreducible_unresolved"
                result["reason"] = "no node-addon-api version could be resolved for the compiler probe"

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
            and pp[k].get("unresolved_reason") == "CMAKE_JS_EXTERNAL_DEFAULT"]
    print(f"Reconstructing {len(keys)} cmake-js/node-addon-api packages", file=sys.stderr)

    out = {}
    for i, key in enumerate(keys, 1):
        pkg, version = key.rsplit("@", 1)
        s = sample_by_key[key]
        print(f"\n[{i}/{len(keys)}] {key} ...", file=sys.stderr)
        r = reconstruct_one(pkg, version, s["tarball_url"], s["tarball_sha256"])
        out[key] = r
        print(f"  -> {r.get('final_status')} ({r.get('reason', r.get('evidence_citation', ''))[:150]})",
              file=sys.stderr)
        with open(os.path.join(RESULTS_DIR, "cmakejs_reconstruction.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True, default=str)

    print("\n=== SUMMARY ===")
    counts = {}
    for v in out.values():
        counts[v["final_status"]] = counts.get(v["final_status"], 0) + 1
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
