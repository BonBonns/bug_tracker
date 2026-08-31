#!/usr/bin/env python3
"""R06/FIX01I integration (item 3): real regression for promote_via_js_linkage.py.

Uses REAL cached facts wherever real facts exist (Cartesi's own raw C++ facts and normalized
cpp_facts.json -- independently verified real earlier in this integration's own development;
node-libcurl's own real raw facts and R06 output). The ONE disclosed synthetic piece is a
JS-side call fixture (`build_js_control.py`'s own output) standing in for a real JS call
Cartesi's own currently-published package does not contain -- see that file's own module
docstring and R06_FIX01I_INTEGRATION.md for the full, honest account of why.

SKIPPED (not FAILED) if the real cached fixture paths aren't present in this environment --
this test depends on real, large corpus facts this repo does not commit (multi-MB raw TSVs),
same real-data-dependency discipline as test_target_scoping.py's own node-libcurl regression.

Run: python3 tests/test_promote_via_js_linkage.py   (exit 0 = PASS or SKIP)
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from promote_via_js_linkage import (extract_instancemethod_bindings, link_calls_extended,
                                     promote_findings,
                                     find_callback_info_index_source_for_acquisition)

CARTESI_RAW = "/tmp/cartesi_raw"
CARTESI_CPP_FACTS = "/tmp/smoke_test_cartesi/work/cpp_facts.json"
CARTESI_R06_OUT = "/tmp/cartesi_r06_out_v2.json"
LIBCURL_RAW = "/tmp/npm_corpus_pilot/99910/work/cpp_raw"
LIBCURL_R06_OUT = "/tmp/r06_libcurl_out.json"
SYNTH_JS_DIR = os.path.join(os.path.dirname(HERE), "study", "r06_fix01i_integration",
                             "controls", "cartesi_shape_positive")
SYNTH_JS_PATH = os.path.join(SYNTH_JS_DIR, "js_facts_adapted.json")


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond


def all_present(*paths):
    return all(os.path.exists(p) for p in paths)


ok = True

# --- Real: node-libcurl -- ReadFunction has no CallbackInfo parameter at all (a libcurl-
# invoked callback, never JS-reachable) -- the structural search must find nothing, and the
# finding (already CONTRACT_NOT_APPLICABLE from item 1) is never promoted. ---
print('=== Real: node-libcurl (rejection case) ===')
if all_present(LIBCURL_RAW, LIBCURL_R06_OUT):
    r06 = json.load(open(LIBCURL_R06_OUT))
    for f in r06["findings"]:
        src = find_callback_info_index_source_for_acquisition(
            LIBCURL_RAW, f["method_id"], f["acquisition_call_id"])
        ok &= check(f"{f['method_name']}: no structural CallbackInfo-index source found "
                    "(ReadFunction's real params are char*/size_t/size_t/void*, none is "
                    "Napi::CallbackInfo)", src is None, str(src))
else:
    print("SKIP (real cached facts not present in this environment)")

# --- Real: Cartesi's own real facts -- registration IS structurally found (real, new
# InstanceMethod/DefineClass recognition), but NO real JS call links to it (Cartesi's own
# published dist bundle is WASM/minified, confirmed by direct inspection) -- promotion must
# correctly NOT fire on real data alone. ---
print('=== Real: Cartesi (registration found, real linkage absent -- correctly unpromoted) ===')
if all_present(CARTESI_RAW, CARTESI_CPP_FACTS, CARTESI_R06_OUT):
    cpp = json.load(open(CARTESI_CPP_FACTS))
    table, _audit = extract_instancemethod_bindings(cpp)
    ok &= check("real InstanceMethod registrations found (readMemory/readVirtualMemory/"
                "readConsoleOutput)",
                all(name in table for name in
                    ("readMemory", "readVirtualMemory", "readConsoleOutput")),
                str(sorted(table)[:10]))

    # A minimal js doc with NO calls at all -- stands in for Cartesi's own real published JS
    # facts, which (confirmed via direct inspection) contain zero calls naming any of these.
    empty_js = {"schema": "x", "calls": [], "functions": [], "identifiers": [], "locals": []}
    _, linked, _ = link_calls_extended(empty_js, cpp)
    ok &= check("no real JS calls link to any Cartesi method (real data)", linked == [])

    r06 = json.load(open(CARTESI_R06_OUT))
    for f in r06["findings"]:
        src = find_callback_info_index_source_for_acquisition(
            CARTESI_RAW, f["method_id"], f["acquisition_call_id"])
        ok &= check(f"{f['method_name']}: real structural info[N]-via-out-parameter source found",
                    src is not None, str(src))
    results = promote_findings(r06["findings"], CARTESI_RAW, linked)
    ok &= check("none of Cartesi's real findings promoted (no real JS linkage exists)",
                all(not r["promoted"] for r in results))
else:
    print("SKIP (real cached facts not present in this environment)")

# --- Disclosed synthetic: the JS-call-site half only, C++ side is Cartesi's own real facts.
print('=== Disclosed synthetic: full promotion chain, positive + negative ===')
if all_present(CARTESI_RAW, CARTESI_CPP_FACTS, CARTESI_R06_OUT, SYNTH_JS_PATH):
    cpp = json.load(open(CARTESI_CPP_FACTS))
    js = json.load(open(SYNTH_JS_PATH))
    r06 = json.load(open(CARTESI_R06_OUT))

    _, linked, _ = link_calls_extended(js, cpp)
    results = promote_findings(r06["findings"], CARTESI_RAW, linked)
    rm = next(r for r in results if r["finding"]["method_name"] == "ReadMemory")
    ok &= check("ReadMemory promoted when a real 2-argument JS call links to it (synthetic "
                "JS call site, real C++ facts)", rm["promoted"] is True, str(rm))
    if rm["promoted"]:
        ok &= check("promotion evidence cites info[1] -> JS argument index 2 (1-based, "
                    "index 0 reserved for receiver -- the real off-by-one this integration "
                    "found and fixed)",
                    rm["evidence"]["callback_info_index"] == 1
                    and rm["evidence"]["js_argument_index"] == 2, str(rm["evidence"]))

    # Negative: same call, but missing the 'length' argument (info[1] would be undefined).
    js_missing = json.loads(json.dumps(js))
    js_missing["calls"][0]["arguments"] = [js_missing["calls"][0]["arguments"][0]]
    _, linked_missing, _ = link_calls_extended(js_missing, cpp)
    results_missing = promote_findings(r06["findings"], CARTESI_RAW, linked_missing)
    rm_missing = next(r for r in results_missing if r["finding"]["method_name"] == "ReadMemory")
    ok &= check("ReadMemory NOT promoted when the JS call supplies only 1 argument "
                "(info[1]/index-2 would be a real out-of-bounds/undefined JS read)",
                rm_missing["promoted"] is False, str(rm_missing))
else:
    print("SKIP (real cached facts / synthetic control not present in this environment -- "
          f"run {SYNTH_JS_DIR}/build_js_control.py first)")

print()
print('OVERALL:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
