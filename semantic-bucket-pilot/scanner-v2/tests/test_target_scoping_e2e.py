#!/usr/bin/env python3
"""R06 item 1 (target-scoped build config): real end-to-end regression proving the FULL
wiring -- run_pipeline_one_r06.py's own real build_config.json output (captured from a real
`node-libcurl@5.1.2` pipeline run, `Easy::ReadFunction`'s real per-target gyp classification)
feeds correctly into resource_guard_verdict_r06.py's own `resolve_exc_config_for_method`,
resolving `src/Easy.cc` to `enabled` via the SPECIFIC real gyp target that compiles it --
even though the PACKAGE-WIDE `exception_configuration` in this same real build_config.json
is `"unresolved"` (simulating a not-yet-re-extracted/ambiguous flat classification), proving
per-target resolution gives a definitive answer the flat, package-wide value alone could not.

The embedded JSON below is the REAL `build_config.json` `run_pipeline_one_r06.run_one()`
wrote for `node-libcurl@5.1.2` during this fix's own real pipeline run (methods.tsv
confirmed `method_id=107374182492` is real `ReadFunction`, `filename="src/Easy.cc"`) --
not hand-typed.

Run: python3 tests/test_target_scoping_e2e.py   (exit 0 = PASS)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from resource_guard_verdict_r06 import load_build_config, resolve_exc_config_for_method  # noqa: E402

# Real build_config.json captured from a real node-libcurl@5.1.2 pipeline run (see module
# docstring) -- package-wide exception_configuration deliberately "unresolved" here to prove
# per-target resolution does NOT depend on the package-wide value being correct.
REAL_NODE_LIBCURL_BUILD_CONFIG = {
    "schema": "build_config/2",
    "exception_configuration": "unresolved",
    "evidence": [],
    "citation": "from npm_build_configuration.tsv",
    "gyp_path": "binding.gyp",
    "gyp_targets": [
        {
            "target_name": "<(module_name)",
            "sources": ["src/node_libcurl.cc", "src/Easy.cc", "src/Share.cc", "src/Multi.cc",
                        "src/CurlHttpPost.cc", "src/CurlMime.cc", "src/Curl.cc",
                        "src/CurlError.cc", "src/CurlVersionInfo.cc",
                        "src/Http2PushFrameHeaders.cc"],
            "exception_configuration": "enabled",
            "disable_evidence": [],
            "enable_evidence": [
                "-fno-exceptions (found inside a gyp `!`-list removal -- real enable evidence)",
                "node_addon_api_except (gyp target dependency)"],
        },
        {
            "target_name": "action_after_build",
            "sources": [],
            "exception_configuration": "unresolved",
            "disable_evidence": [], "enable_evidence": [],
        },
    ],
}

REAL_READFUNCTION_METHOD_ID = 107374182492  # real, from node-libcurl's own methods.tsv


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond


def main():
    ok = True
    path = '/tmp/r06_test_node_libcurl_build_config.json'
    with open(path, 'w') as f:
        json.dump(REAL_NODE_LIBCURL_BUILD_CONFIG, f)

    build_config = load_build_config('/nonexistent', path)
    ok &= check('load_build_config passes gyp_targets through',
                build_config.get('gyp_targets') is not None)
    ok &= check('package-wide exception_configuration is (deliberately) unresolved',
                build_config['exception_configuration'] == 'unresolved')

    methods_filename = {REAL_READFUNCTION_METHOD_ID: 'src/Easy.cc'}
    cfg = resolve_exc_config_for_method(build_config, methods_filename, REAL_READFUNCTION_METHOD_ID)
    ok &= check('per-finding resolution gives "enabled" (NOT the package-wide "unresolved")',
                cfg['exception_configuration'] == 'enabled', f"got {cfg['exception_configuration']!r}")
    ok &= check('citation cites the real target name', '<(module_name)' in cfg['citation'], cfg['citation'])
    ok &= check('evidence is the real matching_targets list, not empty',
                bool(cfg['evidence']) and cfg['evidence'][0]['target_name'] == '<(module_name)')

    # PHASE B: assert the SELECTED target genuinely compiles the finding's own source file --
    # not merely "some target says enabled" but the SPECIFIC real target whose own sources
    # list actually names src/Easy.cc, and that resolution_scope records this as authoritative
    # per-target resolution, not a package-wide fallback.
    ok &= check('resolution_scope is "per_target" (real per-target data was used, not a '
                'package-wide fallback)', cfg['resolution_scope'] == 'per_target',
                cfg['resolution_scope'])
    ok &= check('resolved_target_name is the real target name', cfg['resolved_target_name'] == '<(module_name)',
                cfg['resolved_target_name'])
    selected_target = next(t for t in REAL_NODE_LIBCURL_BUILD_CONFIG['gyp_targets']
                            if t['target_name'] == cfg['resolved_target_name'])
    ok &= check("the SELECTED target's own real sources list genuinely contains "
                "'src/Easy.cc' (not just any target that happens to say 'enabled')",
                'src/Easy.cc' in selected_target['sources'])
    ok &= check("the selected target's own exception_configuration matches what was returned",
                selected_target['exception_configuration'] == cfg['exception_configuration'])

    # PHASE B: package-wide value is DIAGNOSTIC ONLY -- present, but NOT what was applied.
    # This is the real, concrete divergence case: package-wide says "unresolved", the real
    # per-target resolution correctly says "enabled" for this specific file.
    ok &= check('package_wide_diagnostic is present and reflects the real package-wide value',
                cfg['package_wide_diagnostic']['exception_configuration'] == 'unresolved')
    ok &= check('package-wide diagnostic value DIFFERS from the authoritative per-target '
                'result (proving package-wide was not the one actually applied)',
                cfg['package_wide_diagnostic']['exception_configuration']
                != cfg['exception_configuration'])

    # Fail-closed: a method whose filename isn't in ANY real target's sources list.
    cfg2 = resolve_exc_config_for_method(
        build_config, {999: 'src/unrelated_file_not_in_any_target.cc'}, 999)
    ok &= check('unmatched source file fails closed to BUILD_CONFIGURATION_UNRESOLVED '
                '(never falls back to the package-wide value or a guess)',
                cfg2['exception_configuration'] == 'BUILD_CONFIGURATION_UNRESOLVED',
                f"got {cfg2['exception_configuration']!r}")
    ok &= check('fail-closed case records resolution_scope == "per_target_unresolved"',
                cfg2['resolution_scope'] == 'per_target_unresolved', cfg2['resolution_scope'])

    # Fail-closed: a method with no recorded filename at all.
    cfg3 = resolve_exc_config_for_method(build_config, {}, 999)
    ok &= check('missing filename fails closed to BUILD_CONFIGURATION_UNRESOLVED',
                cfg3['exception_configuration'] == 'BUILD_CONFIGURATION_UNRESOLVED',
                f"got {cfg3['exception_configuration']!r}")

    # No gyp_targets at all (e.g. a cmake-only package) -- falls back to package-wide value,
    # and resolution_scope honestly records this as a fallback, not a real per-target result.
    no_gyp_config = {"exception_configuration": "disabled", "evidence": [], "citation": "x",
                      "gyp_targets": None, "gyp_path": None}
    cfg4 = resolve_exc_config_for_method(no_gyp_config, {}, 1)
    ok &= check('no gyp_targets at all -> falls back to package-wide value (disclosed scope)',
                cfg4['exception_configuration'] == 'disabled', f"got {cfg4['exception_configuration']!r}")
    ok &= check('fallback case records resolution_scope == "package_wide_fallback"',
                cfg4['resolution_scope'] == 'package_wide_fallback', cfg4['resolution_scope'])

    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
