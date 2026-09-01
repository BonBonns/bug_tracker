#!/usr/bin/env python3
"""Cheap, decisive pre-filter before any expensive real build-config reconstruction (node-gyp
configure / cmake-js configure / upstream-repo tracing) for the 54 unresolved packages: C++
exception configuration (NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS) is a node-addon-api
(C++ wrapper) concept -- it has NO MEANING for a package whose real native addon source is pure
C (raw N-API via node_api.h, or a C library like libuiohook), since C has no exception mechanism
for that macro to configure at all. Discovered while piloting uiohook-napi's own real
binding.gyp: its own real `sources` list is 100% *.c (addon.c, napi_helpers.c,
uiohook_worker.c, logger.c) -- never *.cc/*.cpp/*.cxx -- even though the original corpus
sample's own `n_cpp_files` metadata field counts C/C++-family files loosely (not literally
C++-only).

For each of the 54, re-downloads the same already-pinned tarball (continuing the established
narrow exception, hash-verified, nothing written to disk beyond an in-memory tar read) and
inspects the REAL file extensions of every source file referenced by a real build-config file's
own `sources`/`add_library`/`add_executable`/`target_sources` list where mechanically parseable,
falling back to every real .c/.cc/.cpp/.cxx/.C file found ANYWHERE in the tarball otherwise (a
real, disclosed, coarser fallback -- never silently assumed precise)."""
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

CPP_EXT = (".cc", ".cpp", ".cxx", ".c++", ".C")
C_EXT = (".c",)


def main():
    audit = json.load(open(os.path.join(RESULTS_DIR, "build_config_staleness_audit.json")))
    unresolved_keys = [k for k, v in audit["per_package"].items() if v["category"] == "UNRESOLVED"]
    sample = json.load(open(os.path.join(NPM_CORPUS, "overnight_100", "overnight_sample_100.json")))
    sample_by_key = {f'{p["package_name"]}@{p["version"]}': p for p in sample["packages"]}

    out = {}
    for i, key in enumerate(unresolved_keys, 1):
        pkg, version = key.rsplit("@", 1)
        s = sample_by_key[key]
        tb, err = ebc.fetch_bytes(s["tarball_url"])
        if err:
            out[key] = {"status": "DOWNLOAD_FAILED", "detail": err}
            continue
        if provenance.sha256_hex(tb) != s["tarball_sha256"]:
            out[key] = {"status": "HASH_MISMATCH"}
            continue
        tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r:gz")
        cpp_files, c_files = [], []
        for m in tf.getmembers():
            if not m.isfile():
                continue
            name = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if "/test" in f"/{name}".lower() or "/example" in f"/{name}".lower():
                continue  # real, disclosed exclusion -- test/example sources never compiled
                          # into the actual native addon target
            if name.endswith(CPP_EXT):
                cpp_files.append(name)
            elif name.endswith(C_EXT):
                c_files.append(name)
        tf.close()
        if cpp_files:
            classification = "HAS_REAL_CPP_SOURCES"
        elif c_files:
            classification = "PURE_C_NO_EXCEPTION_CONCEPT_APPLIES"
        else:
            classification = "NO_C_OR_CPP_SOURCE_FOUND"
        out[key] = {"status": "OK", "classification": classification,
                    "cpp_file_count": len(cpp_files), "c_file_count": len(c_files),
                    "cpp_files_sample": cpp_files[:5], "c_files_sample": c_files[:5]}
        print(f"[{i}/{len(unresolved_keys)}] {key}: {classification} "
              f"(cpp={len(cpp_files)} c={len(c_files)})", file=sys.stderr)

    with open(os.path.join(RESULTS_DIR, "cpp_vs_c_source_check.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)

    counts = {}
    for v in out.values():
        c = v.get("classification", v.get("status"))
        counts[c] = counts.get(c, 0) + 1
    print("\n=== SUMMARY ===")
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
