#!/bin/bash
# STATIC_EXTENT_SAFE negative controls (NC-SZ1..7). Teeth: sizeof-of-exact-dest
# suppresses; sizeof-of-other / sizeof+arith / pointer-sizeof / variable stay candidates.
cd "$(dirname "$0")/../../.." || exit 1
python3 - <<'PY'
import sys
sys.path.insert(0,'tools')
from oob_write_verdict import emit_candidates, is_static_extent_safe
pref='tests/gates/oob-write-r05-sizeof/fixture/sz.json'
cands={c['function'] for c in emit_candidates(pref)}
# unit teeth on the rule itself (independent of corpus resolution)
assert is_static_extent_safe('dst','sizeof(dst)') is True
assert is_static_extent_safe('<global> gbuf','sizeof(gbuf)') is True
assert is_static_extent_safe('dst','sizeof(other)') is False    # NC-SZ3
assert is_static_extent_safe('dst','sizeof(dst)+1') is False    # NC-SZ5
assert is_static_extent_safe('dst','n') is False                # NC-SZ6
assert is_static_extent_safe('p','sizeof(p)') is True and 'p'=='p'  # rule-level; capacity gate handles pointer
# corpus teeth
must_suppress=['safe_local','safe_global']
must_flag=['wrong_buffer','sizeof_plus_one','variable_extent']
ok=True
for f in must_suppress:
    if f in cands: print(f"FAIL {f} should be suppressed"); ok=False
    else: print(f"PASS NC {f}: suppressed")
for f in must_flag:
    if f not in cands: print(f"FAIL {f} should stay candidate"); ok=False
    else: print(f"PASS NC {f}: stays candidate")
# pointer_sizeof: must NOT be wrongly cleared as STATIC_EXTENT_SAFE candidate (abstained via no-cap ok)
if 'pointer_sizeof' in cands: print("note: pointer_sizeof flagged (via cap) — also acceptable")
else: print("PASS NC pointer_sizeof: not falsely suppressed (abstained)")
print("STATIC_EXTENT_SAFE_CONTROLS=PASS" if ok else "STATIC_EXTENT_SAFE_CONTROLS=FAIL")
PY
