#!/usr/bin/env python3
"""Read-only investigation (no extractor changes made here) of the 54 packages
audit_build_config_staleness.py left UNRESOLVED. Re-downloads the same 54 already-pinned
tarballs (continuing the same narrow download exception, same tarball_url/tarball_sha256
identity, hash-verified, nothing written to disk), and for each one:
  - confirms real R04/R05/R06 finding counts (relevance bucket 1)
  - records binding_family from the frozen sample metadata (relevance buckets 2/3)
  - extracts REAL, bounded raw text evidence from every real config file found (binding.gyp/
    CMakeLists.txt/*.cmake/meson.build/package.json), specifically checking for the concrete,
    mechanically-verifiable signals a fix could act on:
      * bare `node_addon_api` gyp dependency (NOT `_except`) -- real, disclosed evidence the
        exception-enabling target was NOT chosen, distinct from finding no evidence at all
      * `cmake-js` in package.json devDependencies/dependencies -- explains why a CMake-based
        package's own CMakeLists.txt never mentions NAPI_CPP_EXCEPTIONS/-fexceptions textually
        (cmake-js injects the define itself, at build time, outside the package's own repo)
      * any config file present at all vs. none (package.json only)
No conclusions are pre-baked here -- this is the real evidence gathering step feeding the
manual categorization in UNRESOLVED_CATEGORIZATION.md."""
import io
import json
import os
import re
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
NPM_CORPUS = os.path.join(SCANNER_V2, "npm_corpus")
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, NPM_CORPUS)
import provenance  # noqa: E402
import extract_build_config as ebc  # noqa: E402

BARE_NODE_ADDON_API_RE = re.compile(rb'node_addon_api(?!_except)')
CMAKE_JS_RE = re.compile(rb'cmake-js')
NAPI_VERSION_RE = re.compile(rb'NAPI_VERSION')


def load_replayed():
    idents = []
    with open(os.path.join(RESULTS_DIR, "replay_records_v5.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            if d.get("outcome") == "REPLAYED":
                idents.append(d)
    return idents


def main():
    audit = json.load(open(os.path.join(RESULTS_DIR, "build_config_staleness_audit.json")))
    unresolved_keys = [k for k, v in audit["per_package"].items() if v["category"] == "UNRESOLVED"]
    sample = json.load(open(os.path.join(NPM_CORPUS, "overnight_100", "overnight_sample_100.json")))
    sample_by_key = {f'{p["package_name"]}@{p["version"]}': p for p in sample["packages"]}
    v5_by_key = {f'{d["package_name"]}@{d["version"]}': d for d in load_replayed()}

    out = {}
    for i, key in enumerate(unresolved_keys, 1):
        pkg, version = key.rsplit("@", 1)
        s = sample_by_key[key]
        rec = v5_by_key.get(key, {})
        r04 = rec.get("r04_findings") or []
        r05 = rec.get("r05_findings") or []
        r06 = rec.get("r06_findings") or []

        tb, err = ebc.fetch_bytes(s["tarball_url"])
        entry = {"binding_family": s.get("binding_family"),
                 "build_systems_metadata": s.get("build_systems"),
                 "r04_count": len(r04), "r05_count": len(r05), "r06_count": len(r06)}
        if err:
            entry["download_error"] = err
            out[key] = entry
            print(f"[{i}/{len(unresolved_keys)}] {key}: DOWNLOAD_FAILED", file=sys.stderr)
            continue
        real_sha = provenance.sha256_hex(tb)
        if real_sha != s["tarball_sha256"]:
            entry["hash_mismatch"] = True
            out[key] = entry
            continue

        try:
            tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r:gz")
        except Exception as e:
            entry["tarball_unreadable"] = str(e)
            out[key] = entry
            continue

        found_files = []
        has_bare_node_addon_api = False
        has_cmake_js = False
        has_napi_version_only = False
        real_config_bytes = 0
        for m in tf.getmembers():
            if not m.isfile():
                continue
            name = m.name.split("/", 1)[1] if "/" in m.name else m.name
            lower = name.lower()
            family = None
            for suffix, fam in ebc.CONFIG_FILE_SUFFIXES.items():
                if lower.endswith(suffix):
                    family = fam
                    break
            if family is None:
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            try:
                content = f.read()
            except Exception:
                continue
            found_files.append(name)
            real_config_bytes += len(content)
            if BARE_NODE_ADDON_API_RE.search(content):
                has_bare_node_addon_api = True
            if CMAKE_JS_RE.search(content):
                has_cmake_js = True
            if NAPI_VERSION_RE.search(content) and not (
                    ebc.DISABLE_PATTERNS[0][0].search(content) or ebc.DISABLE_PATTERNS[1][0].search(content)
                    or ebc.ENABLE_PATTERNS[0][0].search(content) or ebc.ENABLE_PATTERNS[1][0].search(content)
                    or ebc.ENABLE_PATTERNS[2][0].search(content)):
                has_napi_version_only = True
        tf.close()

        entry.update({
            "found_config_files": found_files,
            "has_bare_node_addon_api_dependency": has_bare_node_addon_api,
            "has_cmake_js_reference": has_cmake_js,
            "napi_version_macro_present_no_exception_evidence": has_napi_version_only,
            "no_recognized_build_file": found_files == [] or all(
                f.lower().endswith("package.json") for f in found_files),
        })
        out[key] = entry
        print(f"[{i}/{len(unresolved_keys)}] {key}: files={found_files} "
              f"bare_node_addon_api={has_bare_node_addon_api} cmake_js={has_cmake_js}",
              file=sys.stderr)

    with open(os.path.join(RESULTS_DIR, "unresolved_investigation.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)

    # summary counts
    no_build_file = sum(1 for v in out.values() if v.get("no_recognized_build_file"))
    bare_dep = sum(1 for v in out.values() if v.get("has_bare_node_addon_api_dependency"))
    cmake_js = sum(1 for v in out.values() if v.get("has_cmake_js_reference"))
    print("\n=== SUMMARY ===")
    print(f"no_recognized_build_file (package.json only): {no_build_file}")
    print(f"has_bare_node_addon_api_dependency (real, not _except): {bare_dep}")
    print(f"has_cmake_js_reference: {cmake_js}")
    print(f"total investigated: {len(out)}")


if __name__ == "__main__":
    main()
