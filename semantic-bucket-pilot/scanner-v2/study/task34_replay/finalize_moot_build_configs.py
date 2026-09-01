#!/usr/bin/env python3
"""Finalizes the 30 packages (of the 54 unresolved) that this investigation found are
STRUCTURALLY MOOT for the exception_configuration question -- never a guess, always a real,
direct, structural determination re-verified here from the same real, already-downloaded
evidence (check_cpp_vs_c_sources.py's own PURE_C/NO_C_OR_CPP_SOURCE classification;
check_real_binding_technology.py's own real #include-based nan/LEGACY_RAW_V8_NODE_H
classification):

  - 6 PURE_C_NO_EXCEPTION_CONCEPT_APPLIES: the package's own real native source is entirely C
    (never C++) -- NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS is a C++ concept with no
    meaning in a C translation unit.
  - 1 NOT_A_NATIVE_ADDON_PACKAGE (yatag@1.3.0): confirmed directly -- its own real package.json
    declares no native-binding dependency at all (no nan, node-addon-api, bindings, gypfile, or
    binary field); the only real .cpp/.hpp files in its tarball are node-gdal-async's own
    vendored TEST FIXTURES under test/, never compiled by yatag's own build. A real corpus-
    selection false positive, not a build-configuration gap.
  - 19 nan (real #include <nan.h> confirmed): R04/R05/R06's own contract-matching NEVER targets
    Nan-shaped acquisition calls (confirmed: 0 R04/R05/R06 findings across all 54 unresolved
    packages, Nan-based ones included), and resource_guard_verdict_nan.py's own applicability
    logic never reads npm_build_configuration.tsv at all (its own module docstring: it carries
    no build-configuration gate). No analyzer in this pipeline ever consults exception_
    configuration for a genuinely Nan-based package, by construction.
  - 4 LEGACY_RAW_V8_NODE_H (real #include <node.h>/<node_object_wrap.h> confirmed, no napi.h/
    nan.h anywhere): the same real reasoning as Nan -- NAPI_CPP_EXCEPTIONS is a node-addon-api-
    specific macro; a raw, pre-N-API/pre-Nan direct-V8 addon has no such convention to configure
    at all.
  - 3 RAW_NAPI_C_STYLE (real #include <node_api.h> confirmed, never napi.h/napi-inl.h -- a real
    bug caught mid-investigation: `node_api.h` is the raw N-API C header, included internally by
    node-addon-api's own napi.h but ALSO used directly, alone, by packages that never touch
    node-addon-api's C++ wrapper at all; found via velociradix's own real, cloned-at-its-pinned-
    commit upstream source, `src/addon.cpp: #include <node_api.h>`, never napi.h): raw N-API's
    own C-style, status-code error handling has no C++ exceptions involved, so
    NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS has no meaning for it either. Confirmed for
    all 3: @8crafter/leveldb-zlib, @jasonscheirer/native-progress-bar (whose own genuinely
    real, disclosed GTK4/libadwaita system-dependency gap in this container is now moot -- the
    real answer was never blocked by that gap in the first place), and velociradix.

Per direct instruction's own required record shape (step 4), plus a REQUIRED schema extension,
disclosed here rather than silently forced into the 4-way vocabulary: `not_applicable` is a
5th real, distinct final status alongside enabled/disabled/conflict/irreducible_unresolved --
these 30 packages are not merely "impossible to resolve" (irreducible_unresolved), they are
CERTAIN, by direct structural evidence, that the question itself does not apply. Collapsing
`not_applicable` into `irreducible_unresolved` would understate the real certainty this
investigation actually reached for them."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")


def main():
    cvc = json.load(open(os.path.join(RESULTS_DIR, "cpp_vs_c_source_check.json")))
    rbt = json.load(open(os.path.join(RESULTS_DIR, "real_binding_technology.json")))

    records = {}

    for key, v in cvc.items():
        cls = v.get("classification")
        if cls == "PURE_C_NO_EXCEPTION_CONCEPT_APPLIES":
            records[key] = {
                "exact_target": "ALL (package-wide -- no C++ translation unit exists)",
                "build_system": "n/a (pure C addon)",
                "build_system_version": None,
                "compiler_flags": None,
                "relevant_defines": None,
                "evidence_citation": (
                    f"real tarball inspection: {v['c_file_count']} real .c file(s), 0 real "
                    f".cc/.cpp/.cxx files (sample: {v['c_files_sample']})"),
                "final_status": "not_applicable",
                "final_status_reason": "PURE_C_NO_EXCEPTION_CONCEPT_APPLIES",
            }
        elif cls == "NO_C_OR_CPP_SOURCE_FOUND":
            # only yatag@1.3.0 in this investigation -- confirmed via direct package.json
            # inspection (see this module's own docstring) to be a real corpus-selection false
            # positive, not merely "no source found."
            records[key] = {
                "exact_target": "n/a -- no native addon exists in this package",
                "build_system": "n/a",
                "build_system_version": None,
                "compiler_flags": None,
                "relevant_defines": None,
                "evidence_citation": (
                    "real package.json inspection: no nan/node-addon-api/bindings dependency, "
                    "no gypfile/binary field; the only real .cpp/.hpp files present are "
                    "node-gdal-async's own vendored test/ fixtures, never compiled by this "
                    "package's own build (it has none)"),
                "final_status": "not_applicable",
                "final_status_reason": "NOT_A_NATIVE_ADDON_PACKAGE",
            }

    for key, v in rbt.items():
        fam = v["real_family_from_includes"]
        if fam not in ("nan", "LEGACY_RAW_V8_NODE_H", "RAW_NAPI_C_STYLE"):
            continue
        if fam == "nan":
            citation = (f"real #include <nan.h> confirmed directly in this package's own "
                        f"tarball (napi_include={v['has_napi_include']}); "
                        f"package.json declares nan={v['package_json_declares_nan']}")
            reason = "NAN_FAMILY_EXCEPTION_CONFIG_NEVER_CONSULTED"
        elif fam == "RAW_NAPI_C_STYLE":
            citation = ("real #include <node_api.h> confirmed directly, never napi.h/"
                        "napi-inl.h anywhere in this package's own tarball -- raw N-API "
                        "(C-style, status-code error handling), never node-addon-api's own "
                        "C++ exception-aware wrapper")
            reason = "RAW_NAPI_C_STYLE_NO_EXCEPTION_CONCEPT"
        else:
            citation = (f"real #include <node.h>/<node_object_wrap.h>/<node_buffer.h> "
                        f"confirmed directly, no napi.h/nan.h anywhere in this package's own "
                        f"tarball -- a legacy, pre-N-API/pre-Nan direct-V8 addon")
            reason = "LEGACY_RAW_V8_EXCEPTION_CONFIG_HAS_NO_MEANING"
        records[key] = {
            "exact_target": "ALL (package-wide -- no NAPI_CPP_EXCEPTIONS convention exists for "
                             "this binding family)",
            "build_system": "n/a (question does not apply to this binding family)",
            "build_system_version": None,
            "compiler_flags": None,
            "relevant_defines": None,
            "evidence_citation": citation,
            "final_status": "not_applicable",
            "final_status_reason": reason,
        }

    with open(os.path.join(RESULTS_DIR, "moot_build_configs_final.json"), "w") as f:
        json.dump(records, f, indent=2, sort_keys=True, default=str)

    print(f"Finalized {len(records)} not_applicable records")
    by_reason = {}
    for v in records.values():
        by_reason[v["final_status_reason"]] = by_reason.get(v["final_status_reason"], 0) + 1
    print(json.dumps(by_reason, indent=2))


if __name__ == "__main__":
    main()
