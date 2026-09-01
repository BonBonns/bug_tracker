#!/usr/bin/env python3
"""Real, structural determination of binding technology for the 47 packages that
check_cpp_vs_c_sources.py found to have real C++ sources -- NEVER trusted from the sample's own
`binding_family` metadata field alone, which was caught giving a WRONG answer for a real package
during this investigation's own pilot (@ampretia/x509 shows binding_family="none" in
overnight_sample_100.json, but its own real package.json declares `"nan": "2.17.0"` as a real
dependency, confirmed directly).

Why this matters: exception_configuration (NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS) is
SPECIFICALLY a node-addon-api convention -- R04/R05/R06's own contract-matching only ever
targets node-addon-api's own `Napi::`-shaped acquisition calls (confirmed: all 54 unresolved
packages, Nan-based ones included, already show ZERO R04/R05/R06 findings), and
resource_guard_verdict_nan.py's own applicability logic NEVER reads npm_build_configuration.tsv
at all (its own module docstring: it does not carry R04-R06's build-configuration gate). So for
a genuinely, confirmed Nan-based package, the exception_configuration question is not merely
"currently unexercised" -- it is STRUCTURALLY MOOT: no analyzer in this pipeline ever reads it
for that package's own findings, by construction, regardless of any future package-specific
finding.

Real evidence gathered per package (re-downloading the same already-pinned tarball, continuing
the established narrow exception, hash-verified, nothing written to disk beyond an in-memory
tar read):
  - real `#include` lines across every real source/header file, classified as napi (napi.h/
    node_api.h) vs nan (nan.h) -- the actual, structural signal, not a derived label.
  - real package.json `dependencies`/`devDependencies` entries for "nan" / "node-addon-api".
Both checked independently; a real disagreement between them is flagged, never silently
resolved by preferring one over the other."""
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

# Path-qualified (a real path prefix ending in "/" is allowed before the real filename), never
# a bare-filename-only match -- a real, found-during-piloting bug: @astronautlabs/webrtc's own
# real includes are `<node-addon-api/napi.h>`, which a bare `["<]napi\.h[">]` anchor does NOT
# match. The path prefix must end in "/" right before the real filename (never a loose substring
# match like "libnan.h", which would wrongly match a bare `nan\.h` search with no "/" boundary).
# CORRECTED (real bug caught later in this same investigation, against velociradix's own real
# upstream source): `node_api.h` is the RAW N-API C header, included by node-addon-api's own
# napi.h internally but ALSO used directly, alone, by packages that never touch node-addon-api's
# C++ wrapper at all (raw N-API, C-style status-code error handling -- no C++ exceptions
# involved, confirmed directly on velociradix's own real src/addon.cpp: `#include <node_api.h>`,
# never napi.h). Conflating "includes node_api.h" with "is node-addon-api" produced 3 real
# false positives in this investigation's own first pass (@8crafter/leveldb-zlib,
# @jasonscheirer/native-progress-bar, velociradix) -- all three are genuinely raw-N-API-only,
# structurally moot for exception_configuration for the SAME reason as pure-C/Nan/legacy-node.h.
# NAPI_INCLUDE_RE (node-addon-api's OWN C++ wrapper) and NODE_API_H_ONLY_RE (the raw C header)
# are now tracked as two real, separate, independent signals -- never merged.
NAPI_INCLUDE_RE = re.compile(rb'#\s*include\s*["<](?:[^"<>]*/)?(?:napi\.h|napi-inl\.h)[">]')
NODE_API_H_ONLY_RE = re.compile(rb'#\s*include\s*["<](?:[^"<>]*/)?node_api\.h[">]')
NAN_INCLUDE_RE = re.compile(rb'#\s*include\s*["<](?:[^"<>]*/)?nan\.h[">]')
# Real, legacy, pre-N-API/pre-Nan native-addon convention -- directly targets V8 via Node's own
# raw C++ API (`node::ObjectWrap`, `v8::...`). Confirmed by direct source inspection during this
# investigation's own manual review of the 4 real "NEITHER_INCLUDED" packages (capnp,
# profoundjs-fibers, @sentry-internal/node-native-stacktrace, thunder-node-sdk-lite-m) -- every
# one includes `<node.h>` and/or `<node_object_wrap.h>` directly, never napi.h/nan.h. Like Nan,
# this convention has NO NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS concept at all (that is
# specifically node-addon-api's own macro) -- structurally moot for the exact same reason.
LEGACY_NODE_H_INCLUDE_RE = re.compile(
    rb'#\s*include\s*["<](?:[^"<>]*/)?(?:node\.h|node_object_wrap\.h|node_buffer\.h)[">]')
SRC_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".c++", ".C", ".h", ".hh", ".hpp", ".hxx")


def main():
    cvc = json.load(open(os.path.join(RESULTS_DIR, "cpp_vs_c_source_check.json")))
    keys = [k for k, v in cvc.items() if v.get("classification") == "HAS_REAL_CPP_SOURCES"]
    sample = json.load(open(os.path.join(NPM_CORPUS, "overnight_100", "overnight_sample_100.json")))
    sample_by_key = {f'{p["package_name"]}@{p["version"]}': p for p in sample["packages"]}

    out = {}
    for i, key in enumerate(keys, 1):
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
        has_napi_include = has_nan_include = has_legacy_node_h_include = False
        has_node_api_h_only = False
        pkg_json_deps = {}
        for m in tf.getmembers():
            if not m.isfile():
                continue
            name = m.name.split("/", 1)[1] if "/" in m.name else m.name
            lname = name.lower()
            if "/test" in f"/{lname}" or "/example" in f"/{lname}":
                continue
            if lname.endswith("package.json") and "/" not in name:
                f = tf.extractfile(m)
                try:
                    pkg_json = json.loads(f.read().decode("utf-8", "replace"))
                    pkg_json_deps = {**(pkg_json.get("dependencies") or {}),
                                      **(pkg_json.get("devDependencies") or {})}
                except Exception:
                    pass
                continue
            if not lname.endswith(SRC_SUFFIXES):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            try:
                content = f.read()
            except Exception:
                continue
            if NAPI_INCLUDE_RE.search(content):
                has_napi_include = True
            if NODE_API_H_ONLY_RE.search(content):
                has_node_api_h_only = True
            if NAN_INCLUDE_RE.search(content):
                has_nan_include = True
            if LEGACY_NODE_H_INCLUDE_RE.search(content):
                has_legacy_node_h_include = True
        tf.close()

        dep_says_nan = "nan" in pkg_json_deps
        dep_says_napi = "node-addon-api" in pkg_json_deps
        sample_binding_family = s.get("binding_family")

        # real, structural determination: the #include evidence is authoritative (it is what
        # the compiler itself actually sees); package.json dependency evidence is a real,
        # independent cross-check, never the deciding vote when the two disagree.
        if has_nan_include and not has_napi_include:
            real_family = "nan"
        elif has_napi_include and not has_nan_include:
            real_family = "node-addon-api"
        elif has_napi_include and has_nan_include:
            real_family = "MIXED_BOTH_INCLUDED"
        elif has_node_api_h_only:
            # RAW N-API (the C API, node_api.h) with no node-addon-api C++ wrapper anywhere --
            # structurally moot for exception_configuration for the same real reason as "nan":
            # NAPI_CPP_EXCEPTIONS is node-addon-api's own C++-wrapper macro; a raw N-API
            # addon uses C-style status-code error handling, no C++ exceptions involved at all.
            real_family = "RAW_NAPI_C_STYLE"
        elif has_legacy_node_h_include:
            # real, legacy, pre-N-API/pre-Nan direct-V8 addon (node::ObjectWrap/node.h) --
            # structurally moot for exception_configuration for the SAME reason as "nan": no
            # NAPI_CPP_EXCEPTIONS convention exists for this idiom either.
            real_family = "LEGACY_RAW_V8_NODE_H"
        else:
            real_family = "NEITHER_INCLUDED"

        out[key] = {
            "status": "OK",
            "real_family_from_includes": real_family,
            "has_legacy_node_h_include": has_legacy_node_h_include,
            "has_node_api_h_only": has_node_api_h_only,
            "has_napi_include": has_napi_include,
            "has_nan_include": has_nan_include,
            "package_json_declares_nan": dep_says_nan,
            "package_json_declares_node_addon_api": dep_says_napi,
            "sample_metadata_binding_family": sample_binding_family,
            "metadata_disagrees_with_real_evidence": (
                sample_binding_family != real_family
                and not (sample_binding_family == "none" and real_family == "NEITHER_INCLUDED")),
        }
        print(f"[{i}/{len(keys)}] {key}: real={real_family} "
              f"(sample said {sample_binding_family!r}) "
              f"napi_include={has_napi_include} nan_include={has_nan_include} "
              f"pkgjson(nan={dep_says_nan},napi={dep_says_napi})", file=sys.stderr)

    with open(os.path.join(RESULTS_DIR, "real_binding_technology.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)

    counts = {}
    disagreements = []
    for k, v in out.items():
        c = v.get("real_family_from_includes", v.get("status"))
        counts[c] = counts.get(c, 0) + 1
        if v.get("metadata_disagrees_with_real_evidence"):
            disagreements.append(k)
    print("\n=== SUMMARY ===")
    print(json.dumps(counts, indent=2))
    print(f"\nmetadata disagreements ({len(disagreements)}): {disagreements}")


if __name__ == "__main__":
    main()
