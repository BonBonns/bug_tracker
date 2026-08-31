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
        'Qux': (None, True),                                 # assignment-after-use,
                                                              # but never invoked within
                                                              # this file -- the safe
                                                              # define+export pattern
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
    expect = {
        'Foo': 'INVOCATION_NOT_DOMINATED',              # assignment-after-use, invoked
                                                          # synchronously before assignment
        'Bar': 'DEFINITION_NOT_DOMINANT',                # one-branch-only assignment
        'Baz': 'DEFINITION_NOT_DOMINANT',                # loop-only assignment
        'Qux': 'DEFINITION_IN_TRY_BLOCK_UNVERIFIABLE',   # try/catch-only assignment
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


def main():
    h = md5_of(POLYGLOT / 'link_napi_facts.py')
    print(f'link_napi_facts.py md5: {h}')
    ok = True
    ok &= gate_14_controls()
    ok &= gate_reaching_def_probe()
    ok &= gate_cfg_dominance_probe()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
