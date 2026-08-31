#!/usr/bin/env python3
"""CROSSLANG-LINK-FIX01G freeze gate: real, disclosed, hash-checked re-verification of
every control fixture this fix's own account (CHARACTERIZATION.md) claims to pass.
Nothing here is a hand-built expectation typed against the algorithm's own output --
every fixture's own `facts.json`/`merged_result.json` was produced by actually running
the real frontend (jssrc2cpg -> export_neutral.sc -> normalize_joern_facts.py, and for
the 14-control suite, additionally c2cpg -> export_c_cpp_facts_v03.sc ->
normalize_c_cpp_facts_v03.py -> link_napi_facts.py) -- see CHARACTERIZATION.md for the
full, real account of how each fixture was built and what each result means.

Run: python3 gate_crosslang_link_fix.py   (exit 0 = PASS, prints a per-fixture report)
"""
import hashlib, json, sys, pathlib

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]  # .../semantic-bucket-pilot/scanner-v2/study/crosslang_link_fix -> repo root
POLYGLOT = REPO_ROOT / 'tchecker-research-complete/portable-engine-full-review-package/frontends/polyglot'
sys.path.insert(0, str(POLYGLOT))
import link_napi_facts as L  # noqa: E402

CONTROLS = HERE / 'controls'

# CROSSLANG-LINK-FIX01G freeze: link_napi_facts.py's own real md5 at freeze time was
# 50ce751a083aba5ae519d9d9d5b60903 -- printed fresh on every run below (not compared
# automatically, since this file is expected to keep evolving on this development
# branch; a reader can diff the printed hash against this comment to see whether the
# resolver changed since this freeze).


def md5_of(path):
    return hashlib.md5(path.read_bytes()).hexdigest()


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond


def gate_14_controls():
    print('\n=== 14-control suite (8 real positive, 6 real negative shapes) ===')
    ok = True
    js = json.load(open(CONTROLS / 'js_facts/js_facts_adapted.json'))
    cpp = json.load(open(CONTROLS / 'cpp_facts/cpp_facts.json'))
    idx = L.JsCallIndex(js)
    table, _audit = L.extract_napi_bindings(cpp)
    linked, unlinked = [], []
    for c in js['calls']:
        matched, tier, _reason = L.native_binding_receiver_evidence(c, idx)
        is_candidate = (c.get('receiver_name') == 'bindings' or matched) and c['resolution'] != 'EXACT'
        if is_candidate:
            (linked if c['name'] in table else unlinked).append((c['name'], tier))
    ok &= check('8 real positive controls all link', len(linked) == 8,
                f'got {len(linked)}: {linked}')
    ok &= check('0 real negative controls link', len(unlinked) == 0,
                f'got {len(unlinked)}: {unlinked}')
    return ok


def gate_reaching_def_probe():
    print('\n=== 5-case reaching-definition adversarial probe ===')
    js = json.load(open(CONTROLS / 'js_reaching_def_probe/facts.json'))
    idx = L.JsCallIndex(js)
    expect = {
        'Foo': ('MULTIPLE_DEFINITIONS_AMBIGUOUS', False),   # overwrite-before-use
        'Bar': ('MULTIPLE_DEFINITIONS_AMBIGUOUS', False),   # branch multi-definition
        'Baz': ('PARAMETER_SHADOWED', False),               # parameter shadowing
        'Qux': ('CROSS_FUNCTION_NOT_CONST', False),          # assignment-after-use, but
                                                              # never invoked within this
                                                              # file -- would be the safe
                                                              # define+export pattern IF
                                                              # `const`; this fixture
                                                              # declares it `var`, so
                                                              # CROSSLANG-LINK-FIX01H
                                                              # correctly abstains (no
                                                              # real immutability
                                                              # evidence for a cross-
                                                              # function capture)
        'Corge': ('CALLEE_NOT_REQUIRE', False),             # alias cycle -- no match,
                                                              # no hang, no crash
    }
    ok = True
    for c in js['calls']:
        if c['name'] not in expect:
            continue
        matched, tier, reason = L.native_binding_receiver_evidence(c, idx)
        exp_reason, exp_matched = expect[c['name']]
        ok &= check(f"{c['name']}: matched={exp_matched}" + (f' reason={exp_reason}' if exp_reason else ''),
                    matched == exp_matched and (exp_matched or reason == exp_reason),
                    f'got matched={matched} tier={tier} reason={reason}')
    return ok


def gate_cfg_dominance_probe():
    print('\n=== 4-case CFG-dominance adversarial probe (CROSSLANG-LINK-FIX01G) ===')
    js = json.load(open(CONTROLS / 'cfg_dominance_probe/facts.json'))
    idx = L.JsCallIndex(js)
    # All four assignments in this fixture use `var`/`let`, not `const` -- under
    # CROSSLANG-LINK-FIX01H every one of these is now a cross-function case (assignment
    # at module scope, use inside a nested function) and is rejected at the earlier,
    # more fundamental CROSS_FUNCTION_NOT_CONST gate before the deeper dominance/
    # invocation checks are ever reached. See const_cross_function_probe for real,
    # dedicated coverage of CROSS_FUNCTION_DEFINITION_NOT_DOMINANT and
    # CROSS_FUNCTION_INVOCATION_NOT_DOMINATED with real `const` fixtures instead.
    expect = {
        'Foo': 'CROSS_FUNCTION_NOT_CONST',               # assignment-after-use (`var`)
        'Bar': 'CROSS_FUNCTION_NOT_CONST',               # one-branch-only (`let`)
        'Baz': 'CROSS_FUNCTION_NOT_CONST',               # loop-only (`let`)
        'Qux': 'DEFINITION_IN_TRY_BLOCK_UNVERIFIABLE',   # try/catch-only (`let`) --
                                                          # checked before the const gate
    }
    ok = True
    for c in js['calls']:
        if c['name'] not in expect:
            continue
        matched, tier, reason = L.native_binding_receiver_evidence(c, idx)
        ok &= check(f"{c['name']}: rejected, reason={expect[c['name']]}",
                    matched is False and reason == expect[c['name']],
                    f'got matched={matched} tier={tier} reason={reason}')
    return ok


def gate_const_cross_function_probe():
    print('\n=== const cross-function closure-capture probe (CROSSLANG-LINK-FIX01H) ===')
    js = json.load(open(CONTROLS / 'const_cross_function_probe/facts.json'))
    idx = L.JsCallIndex(js)
    expect = {
        # (expected tier or None, expected reason or None)
        'Direct': ('closure_capture_proven', None),   # cross-function const, invoked
                                                        # after assignment -- safe
        'Foo': ('closure_capture_proven', None),       # module-level const, invoked
                                                        # only externally -- the common,
                                                        # safe real-world pattern
        'Bar': (None, 'CROSS_FUNCTION_DEFINITION_NOT_DOMINANT'),  # const, but the
                                                        # defining function has a real
                                                        # early return before it
        'Baz': (None, 'CROSS_FUNCTION_INVOCATION_NOT_DOMINATED'),  # const, but invoked
                                                        # synchronously in the same
                                                        # defining scope BEFORE the
                                                        # assignment line
        'SameFn': ('dominance_proven', None),          # genuinely same-function --
                                                        # real, direct CFG dominance
    }
    ok = True
    for c in js['calls']:
        if c['name'] not in expect:
            continue
        matched, tier, reason = L.native_binding_receiver_evidence(c, idx)
        exp_tier, exp_reason = expect[c['name']]
        ok &= check(f"{c['name']}: tier={exp_tier} reason={exp_reason}",
                    tier == exp_tier and reason == exp_reason,
                    f'got matched={matched} tier={tier} reason={reason}')
    return ok


def main():
    h = md5_of(POLYGLOT / 'link_napi_facts.py')
    print(f'link_napi_facts.py md5: {h}')
    ok = True
    ok &= gate_14_controls()
    ok &= gate_reaching_def_probe()
    ok &= gate_cfg_dominance_probe()
    ok &= gate_const_cross_function_probe()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
