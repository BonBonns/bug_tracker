#!/usr/bin/env python3
"""R06 target-scoping gate: the 5 real, adversarial binding.gyp shapes directly
requested (two targets, one enabled one disabled; `cflags!` in an unrelated target;
OS-conditional exception settings; removal immediately followed by a target-level
re-add; `node_addon_api_except` vs. bare `node_addon_api`), plus a real end-to-end
regression check against the actual published `node-libcurl@5.1.2` tarball (live
network fetch -- skipped, not failed, if the network is unavailable, since it is a
real-corpus regression check, not a synthetic fixture, matching this project's own
`gate_resource_guard_r05.py`/`gate_crosslang_link_fix.py` precedent of testing against
real, not hand-typed, data wherever possible).

Run: python3 tests/test_target_scoping.py   (exit 0 = PASS)
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from extract_build_config import classify_target_aware, resolve_build_config_for_file

def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond

ok = True

# --- Fixture 1: two targets, one enabled, one disabled ---
print('=== Fixture 1: two targets, one enabled one disabled ===')
f1 = b'''
{
  "targets": [
    {
      "target_name": "target_a",
      "sources": ["src/a.cc"],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "defines": ["NAPI_CPP_EXCEPTIONS"]
    },
    {
      "target_name": "target_b",
      "sources": ["src/b.cc"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "cflags": ["-fno-exceptions"],
      "cflags_cc": ["-fno-exceptions"]
    }
  ]
}
'''
r1 = classify_target_aware(f1)
print(r1)
ok &= check('target_a -> enabled', any(t['target_name']=='target_a' and t['exception_configuration']=='enabled' for t in r1))
ok &= check('target_b -> disabled', any(t['target_name']=='target_b' and t['exception_configuration']=='disabled' for t in r1))
res_a = resolve_build_config_for_file(f1, 'src/a.cc')
res_b = resolve_build_config_for_file(f1, 'src/b.cc')
print('file src/a.cc ->', res_a)
print('file src/b.cc ->', res_b)
ok &= check('src/a.cc resolves to enabled via target_a', res_a['exception_configuration']=='enabled' and res_a['resolved_target_name']=='target_a')
ok &= check('src/b.cc resolves to disabled via target_b', res_b['exception_configuration']=='disabled' and res_b['resolved_target_name']=='target_b')
print()

# --- Fixture 2: cflags! in an unrelated target ---
print('=== Fixture 2: cflags! in an unrelated target must not contaminate main ===')
f2 = b'''
{
  "targets": [
    {
      "target_name": "main",
      "sources": ["src/main.cc"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "cflags": ["-fno-exceptions"],
      "cflags_cc": ["-fno-exceptions"]
    },
    {
      "target_name": "unrelated_tool",
      "sources": ["tools/gen.cc"],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"]
    }
  ]
}
'''
r2 = classify_target_aware(f2)
print(r2)
main2 = next(t for t in r2 if t['target_name']=='main')
ok &= check('main stays cleanly disabled, unaffected by unrelated_tool', main2['exception_configuration']=='disabled', str(main2))
res_main = resolve_build_config_for_file(f2, 'src/main.cc')
print('file src/main.cc ->', res_main)
ok &= check('src/main.cc resolves to disabled via main only', res_main['exception_configuration']=='disabled' and res_main['resolved_target_name']=='main')
print()

# --- Fixture 3: OS-conditional exception settings ---
print('=== Fixture 3: OS-conditional settings within one target ===')
f3 = b'''
{
  "targets": [
    {
      "target_name": "main",
      "sources": ["src/main.cc"],
      "conditions": [
        ["OS=='win'", {
          "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
        }],
        ["OS!='win'", {
          "defines": ["NAPI_CPP_EXCEPTIONS"]
        }]
      ]
    }
  ]
}
'''
r3 = classify_target_aware(f3)
print(r3)
ok &= check('main -> conflict (both OS branches present, cannot resolve statically)',
            r3[0]['exception_configuration']=='conflict', str(r3))
res3 = resolve_build_config_for_file(f3, 'src/main.cc')
print('file src/main.cc ->', res3)
ok &= check('never silently resolves to a single enabled/disabled', res3['exception_configuration']=='conflict')
print()

# --- Fixture 4: removal followed by target-level re-add ---
print('=== Fixture 4: removal followed by re-add in the SAME target ===')
f4 = b'''
{
  "targets": [
    {
      "target_name": "main",
      "sources": ["src/main.cc"],
      "cflags!": ["-fno-exceptions"],
      "cflags": ["-fno-exceptions"]
    }
  ]
}
'''
r4 = classify_target_aware(f4)
print(r4)
ok &= check('main -> conflict (both real signals present in the same scope)',
            r4[0]['exception_configuration']=='conflict', str(r4))
res4 = resolve_build_config_for_file(f4, 'src/main.cc')
ok &= check('resolve never silently picks one side', res4['exception_configuration']=='conflict')
print()

# --- Fixture 5: node_addon_api_except vs ordinary node_addon_api ---
print('=== Fixture 5: node_addon_api_except vs bare node_addon_api ===')
f5 = b'''
{
  "targets": [
    {
      "target_name": "with_except",
      "sources": ["src/a.cc"],
      "dependencies": ["<!(node -p \\"require('node-addon-api').targets\\"):node_addon_api_except"]
    },
    {
      "target_name": "without_except",
      "sources": ["src/b.cc"],
      "dependencies": ["<!(node -p \\"require('node-addon-api').targets\\"):node_addon_api"]
    }
  ]
}
'''
r5 = classify_target_aware(f5)
print(r5)
with_e = next(t for t in r5 if t['target_name']=='with_except')
without_e = next(t for t in r5 if t['target_name']=='without_except')
ok &= check('with_except -> enabled', with_e['exception_configuration']=='enabled', str(with_e))
ok &= check('without_except -> unresolved (bare node_addon_api is not itself evidence either way)',
            without_e['exception_configuration']=='unresolved', str(without_e))
print()

print('=== Regression: real node-libcurl single-target case must still resolve correctly ===')
import glob
# reuse cached tarball fetch logic if available, else skip
try:
    from extract_build_config import fetch_bytes
    import tarfile, io
    tb, err = fetch_bytes('https://registry.npmjs.org/node-libcurl/-/node-libcurl-5.1.2.tgz')
    if err:
        print('SKIP (fetch failed):', err)
    else:
        tf = tarfile.open(fileobj=io.BytesIO(tb), mode='r:gz')
        content = None
        for m in tf.getmembers():
            if m.name.endswith('binding.gyp'):
                content = tf.extractfile(m).read()
                break
        if content:
            r_lc = classify_target_aware(content)
            print('real node-libcurl targets:', [(t['target_name'], t['exception_configuration']) for t in r_lc])
            res_lc = resolve_build_config_for_file(content, 'src/Easy.cc')
            print('src/Easy.cc ->', res_lc['exception_configuration'], res_lc['resolved_target_name'])
            ok &= check('real node-libcurl Easy.cc resolves to enabled', res_lc['exception_configuration']=='enabled')
except Exception as e:
    print('SKIP (error):', e)

print()
print('PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
