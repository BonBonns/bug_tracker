#!/usr/bin/env python3
"""PARAM-R01 gate. Each assertion pins one aspect of "a parameter is mutable
storage". The contract is soundness-first: a stale EXACT on the entry value is a
FAILURE; a conservative MAY where the truth is definite is ACCEPTED and recorded."""
import re, sys
out = open(sys.argv[1]).read()
ok = tot = 0
def s(name):
    m = re.search(r'SUMMARY ' + name + r' resolution=(\S+) proven=\[([^\]]*)\] may=\[([^\]]*)\] unknown=(\S+)', out)
    if not m: return None
    n = lambda x: [int(v) for v in x.split(',') if v.strip()]
    return m.group(1), n(m.group(2)), n(m.group(3)), m.group(4) == 'true'
def ck(name, cond, d=''):
    global ok, tot; tot += 1; ok += bool(cond)
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond else f'  [{d}]'))

r = s('p1_reassign_before_return')
ck('p1 reassignment before return: never a stale EXACT on the entry parameter',
   r and not (r[0] == 'EXACT' and r[1] == [0]), r)
ck('p1 the reassigned source (param 1) is at least POSSIBLE', r and (1 in r[1] or 1 in r[2]), r)

r = s('p2_branch_reassign')
ck('p2 branch-conditional reassignment: never a definite claim', r and r[0] != 'EXACT' or (r and not r[1]), r)
ck('p2 both the entry value and the branch value survive as possibilities',
   r and set(r[1] + r[2]) >= {0, 1}, r)

r = s('p3_self_assign')
ck('p3 self-assignment a=a still attributes to a', r and (0 in r[1] or 0 in r[2]), r)

r = s('p4_chained')
ck('p4 chained a=b;b=c: c is NOT claimed as the origin of a',
   r and 2 not in r[1], r)

r = s('p5_compound')
ck('p5 compound a+=b is never EXACT (prior value survives)',
   r and not (r[0] == 'EXACT' and r[1]), r)
ck('p5 the added operand is at least POSSIBLE', r and (1 in r[1] or 1 in r[2]), r)
# LOSS OF KNOWN PROVENANCE IS A REGRESSION TOO, not only false certainty:
# `a += b` derives from BOTH the prior a and b, so parameter 0 must survive as a
# possible origin. The PARAM-R02 shadow silently erased it while still passing
# every other p5 assertion — which is why this one exists.
ck('p5 compound update PRESERVES the target prior origin (param 0 stays possible)',
   r and (0 in r[1] or 0 in r[2]), r)

r = s('p6_latest_wins')
ck('p6 repeated reassignment: the stale first source is not claimed alone',
   r and r[1] != [1], r)

r = s('p7_dead_after_return')
ck('p7 a function that never reassigns is unaffected: EXACT [0]',
   r and r[0] == 'EXACT' and r[1] == [0], r)

r = s('p8_ptr_param_mutation')
ck('p8 pointer-parameter mutation is distinct from rebinding the parameter',
   r is not None and not (r[0] == 'EXACT' and r[1] == [0]), r)

print(f'CPP_PARAM_R01={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
