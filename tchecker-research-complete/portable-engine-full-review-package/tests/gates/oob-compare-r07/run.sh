#!/bin/bash
# TOR-B2a two-sided OOB_COMPARE negative controls. Teeth: a capacity bound for side A
# must NOT certify side B. n<=cap(A) AND n<=cap(B) required; missing cap or variable n abstains.
cd "$(dirname "$0")/../../.." || exit 1
python3 - <<'PY'
import sys; sys.path.insert(0,'tools')
from oob_compare_verdict import emit_candidates, _const_extent
pref='tests/gates/oob-compare-r07/fixture/cmp.json'
c={x['function'] for x in emit_candidates(pref)}
must_cand={'unsafe_on_b','unsafe_sizeof_a','unsafe_strncmp_b'}  # NC-CMP3,4,6
must_not={'safe_both','safe_min','safe_strncmp','variable_n','ptr_operand'}  # NC-CMP1,2,5,7,8
ok=True
for f in must_cand:
    if f in c: print(f"PASS NC {f}: candidate (wrong-side overrun caught)")
    else: print(f"FAIL {f} should be candidate"); ok=False
for f in must_not:
    if f not in c: print(f"PASS NC {f}: not flagged (safe or abstain)")
    else: print(f"FAIL {f} wrongly flagged"); ok=False
# hard teeth: a bound satisfying A must not certify B
assert _const_extent('32',{})==32 and _const_extent('n',{}) is None
print("OOB_COMPARE_CONTROLS=PASS" if ok else "OOB_COMPARE_CONTROLS=FAIL")
PY
