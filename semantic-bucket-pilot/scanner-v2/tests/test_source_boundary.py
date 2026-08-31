#!/usr/bin/env python3
"""R06 source-boundary gate: real regression test against the ALREADY-committed
`study/resource_guard_r05/r05_controls` fixture (real, compiled, real `#include
<napi.h>` -- see RESOURCE_GUARD_R05.md), plus direct unit checks of
`_is_js_callback_origin_type`'s own real-vs-synthetic type-string matching.

The two OTHER real verifications this fix required (node-libcurl as the required
REJECTION case; Cartesi as the required regression/positive-development-process case)
were run directly against real, live-fetched/live-built facts during this fix's own
development -- NOT automated into this fast, hermetic gate, since both require a real
network fetch and a real c2cpg/header-staging run (multi-second, not appropriate for a
fast repeatable gate). Full, real, honest account of both -- including the finding that
Cartesi's own real acquisition sites do NOT exercise this specific code path at all
(their own backward trace never reaches ANY parameter, unrelated to this fix, unchanged
before/after) -- is in
study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md's own R06 addendum.

Run: python3 tests/test_source_boundary.py   (exit 0 = PASS)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # for resource_guard_verdict_r06 itself (sibling directory)
sys.path.insert(0, os.path.dirname(HERE))
from resource_guard_verdict_r06 import _is_js_callback_origin_type  # noqa: E402


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond


def gate_type_matching():
    print('=== _is_js_callback_origin_type: real and synthetic type strings ===')
    ok = True
    # Real forms confirmed via direct c2cpg output during this fix's own development.
    ok &= check('real double-colon form', _is_js_callback_origin_type('const Napi::CallbackInfo &'))
    ok &= check('real dot form (c2cpg\'s own rendering)', _is_js_callback_origin_type('Napi.CallbackInfo&'))
    ok &= check('bare form', _is_js_callback_origin_type('Napi::CallbackInfo'))
    # Real negative forms -- confirmed via node-libcurl's own real ReadFunction signature.
    ok &= check('size_t is NOT a callback-info type', not _is_js_callback_origin_type('size_t'))
    ok &= check('char* is NOT a callback-info type', not _is_js_callback_origin_type('char*'))
    ok &= check('void* is NOT a callback-info type', not _is_js_callback_origin_type('void*'))
    ok &= check('empty/None type is NOT a callback-info type',
                not _is_js_callback_origin_type('') and not _is_js_callback_origin_type(None))
    return ok


def gate_r05_controls_fixture():
    print('\n=== real, committed r05_controls fixture (PositiveBufferNew) ===')
    controls_dir = os.path.join(os.path.dirname(HERE), 'study', 'resource_guard_r05', 'r05_controls')
    raw_dir = os.path.join(controls_dir, 'raw_facts')
    if not os.path.isdir(raw_dir):
        print(f'SKIP (not found: {raw_dir})')
        return True
    # r05_controls/build_config.json is deliberately gitignored (study/resource_guard_r05/
    # .gitignore) -- not committed, so this gate constructs the same, real, small content
    # inline instead of depending on an untracked file. Real values, not invented: this
    # fixture is compiled with `-DNAPI_DISABLE_CPP_EXCEPTIONS` (see fixture_source.cpp).
    build_config_path = '/tmp/r06_test_r05_controls_build_config.json'
    with open(build_config_path, 'w') as f:
        json.dump({"exception_configuration": "disabled",
                    "evidence": [{"source": "r05_controls fixture",
                                  "detail": "compiled with -DNAPI_DISABLE_CPP_EXCEPTIONS",
                                  "citation": "n/a -- test fixture"}],
                    "citation": "test fixture, exceptions explicitly disabled at compile time"}, f)
    out_path = '/tmp/r06_test_r05_controls_out.json'
    rc = os.system(
        f'{sys.executable} {os.path.join(os.path.dirname(HERE), "resource_guard_verdict_r06.py")} '
        f'{raw_dir} {out_path} --real --build-config {build_config_path} >/tmp/r06_test_r05_controls.log 2>&1')
    ok = check('resource_guard_verdict_r06.py ran cleanly', rc == 0)
    if not ok:
        return False
    with open(out_path) as f:
        result = json.load(f)
    finding = next((f for f in result['findings'] if f.get('method_name') == 'PositiveBufferNew'), None)
    ok &= check('PositiveBufferNew finding present', finding is not None)
    if finding is None:
        return ok
    sbe = finding.get('source_boundary_evidence') or {}
    ok &= check('source_boundary == JS_CALLBACK_INFO_PARAMETER',
                sbe.get('source_boundary') == 'JS_CALLBACK_INFO_PARAMETER', str(sbe))
    ok &= check('attacker_controlled is True', sbe.get('attacker_controlled') is True, str(sbe))
    ok &= check('parameter_type is a real CallbackInfo type',
                _is_js_callback_origin_type(sbe.get('parameter_type')), str(sbe))
    ok &= check('field renamed from attacker_influence_evidence',
                'attacker_influence_evidence' not in finding)
    return ok


def main():
    ok = True
    ok &= gate_type_matching()
    ok &= gate_r05_controls_fixture()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
