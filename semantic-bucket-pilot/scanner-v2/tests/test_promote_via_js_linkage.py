#!/usr/bin/env python3
"""R06/FIX01I integration (item 3): real regression for promote_via_js_linkage.py.

Uses REAL committed facts (task #41): Cartesi's own raw C++ facts and normalized
cpp_facts.json, node-libcurl's own real raw facts and build_config.json -- all committed under
study/r06_fix01i_integration/real_fixtures/ (task #41; previously these lived ONLY in
operator-maintained /tmp paths never committed anywhere -- the exact same failure class that
lost /tmp/cap_corpus, task #42's own FIXTURE_NOTE.md). R06's own output for each is now
REGENERATED fresh by this test (subprocess to resource_guard_verdict_r06.py itself) rather than
read from a precomputed /tmp JSON snapshot, so this test always reflects the CURRENT code, never
a stale cached result. The ONE disclosed synthetic piece is a JS-side call fixture
(`build_js_control.py`'s own output) standing in for a real JS call Cartesi's own
currently-published package does not contain -- see that file's own module docstring and
R06_FIX01I_INTEGRATION.md for the full, honest account of why.

No longer SKIPs on a fresh checkout -- the real fixtures this test needs are committed. A
missing `joern`/environment issue would show up as this file's own subprocess call failing
loudly, not a silent skip.

Run: python3 tests/test_promote_via_js_linkage.py   (exit 0 = PASS)
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

FIXTURES = os.path.join(os.path.dirname(HERE), "study", "r06_fix01i_integration",
                         "real_fixtures")
CARTESI_RAW = os.path.join(FIXTURES, "cartesi_raw")
CARTESI_CPP_FACTS = os.path.join(FIXTURES, "cartesi_cpp_facts.json")
CARTESI_BUILD_CONFIG = os.path.join(FIXTURES, "cartesi_build_config.json")
CARTESI_R06_OUT = os.path.join(FIXTURES, "_generated_cartesi_r06_out.json")
LIBCURL_RAW = os.path.join(FIXTURES, "libcurl_raw")
LIBCURL_BUILD_CONFIG = os.path.join(FIXTURES, "libcurl_build_config.json")
LIBCURL_R06_OUT = os.path.join(FIXTURES, "_generated_libcurl_r06_out.json")
SYNTH_JS_DIR = os.path.join(os.path.dirname(HERE), "study", "r06_fix01i_integration",
                             "controls", "cartesi_shape_positive")
SYNTH_JS_PATH = os.path.join(SYNTH_JS_DIR, "js_facts_adapted.json")

R06_SCRIPT = os.path.join(os.path.dirname(HERE), "resource_guard_verdict_r06.py")


def _regenerate(raw_dir, build_config, out_path):
    """Runs the REAL resource_guard_verdict_r06.py against a committed real raw_dir, writing
    its real output to out_path (gitignored -- generated, not committed; see .gitignore).
    Raises loudly (never silently degrades) if the subprocess itself fails."""
    subprocess.run([sys.executable, R06_SCRIPT, raw_dir, out_path, "--real",
                    "--build-config", build_config], check=True,
                   capture_output=True, text=True)


_regenerate(LIBCURL_RAW, LIBCURL_BUILD_CONFIG, LIBCURL_R06_OUT)
_regenerate(CARTESI_RAW, CARTESI_BUILD_CONFIG, CARTESI_R06_OUT)


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
        ok &= check("promoted verdict is named JS_ARGUMENT_CONTROLLED (the required verdict "
                    "name), with a real, R06-schema-shaped replacement source_boundary_evidence",
                    rm["reason"] == "JS_ARGUMENT_CONTROLLED"
                    and rm["evidence"]["source_boundary"] == "JS_ARGUMENT_CONTROLLED"
                    and rm["evidence"]["attacker_controlled"] is True, str(rm))

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

# --- Adversarial synthetic: a JS-reachable method (real Napi::CallbackInfo parameter) whose
# allocation size is INTERNALLY COMPUTED (length = width * height, no info[N] anywhere) --
# must NEVER be promoted merely because the method is JS-reachable. Required negative: "do
# not promote ... a linked function whose allocation size is literal or internally computed."
print('=== Adversarial: JS-reachable method, internally-computed size -- must not promote ===')
INTERNAL_DIR = os.path.join(os.path.dirname(HERE), "study", "r06_fix01i_integration",
                             "controls", "internally_computed_negative")
if all_present(os.path.join(INTERNAL_DIR, "calls.tsv")):
    src = find_callback_info_index_source_for_acquisition(INTERNAL_DIR, 500000001, 500000014)
    ok &= check("no real info[N]-via-out-parameter source found for an internally-computed "
                "size (width * height, no info[N] access anywhere in the method) -- "
                "'JS-reachable' alone is never sufficient", src is None, str(src))

    # Even if we PRETEND a real FIX01I link exists for this method (worst case for the
    # promotion logic), promote_findings must still refuse, since step (1) already failed.
    fake_finding = {"method_id": 500000001, "acquisition_call_id": 500000014,
                    "source_boundary_evidence": None}
    fake_linked = [{"cpp_function_id": 500000001, "js_call": 1, "name": "allocateBuffer",
                    "js_arguments": [{"index": 1, "code": "n"}, {"index": 2, "code": "m"}],
                    "evidence_tier": "js_receiver_name"}]
    results = promote_findings([fake_finding], INTERNAL_DIR, fake_linked)
    ok &= check("promote_findings refuses even WITH a real (pretend) FIX01I link present, "
                "since no structural info[N] source exists for this internally-computed size",
                results[0]["promoted"] is False, str(results[0]))
else:
    print(f"SKIP (run {INTERNAL_DIR}/build_control.py first)")

print()
print('OVERALL:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
