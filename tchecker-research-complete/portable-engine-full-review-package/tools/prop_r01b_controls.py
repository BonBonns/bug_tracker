#!/usr/bin/env python3
"""PROP-R01b eligibility controls, written BEFORE the rule is implemented.
Each must be shown to accept the safe core and REJECT every hazard shape."""
import sys
from collections import defaultdict

def eligible(read, asg, written, alias_src):
    """The proposed rule, in isolation so controls can exercise it directly."""
    key, base_kind, base_id = read['key'], read['base_kind'], read['base_id']
    if key != 'LITERAL': return False                       # dynamic key
    if base_kind == 'PARAMETER': pass
    elif base_kind == 'LOCAL' and len(asg.get(base_id, [])) == 1: pass
    else: return False                                      # multi-def / no-def / other
    if base_id in written: return False                     # mutation hazard
    src = alias_src.get(base_id)
    if src is not None and src in written: return False      # alias to a mutable object
    return True

ok = tot = 0
def ck(n, c, d=''):
    global ok, tot; tot += 1; ok += bool(c)
    print(('PASS ' if c else 'FAIL ') + n + ('' if c else f'  [{d}]'))

asg = {10: ['def'], 11: ['d1', 'd2'], 12: ['alias-def']}
written = {20, 30}
alias_src = {12: 30}          # local 12 is a second handle to object 30 (mutable)

R = lambda k, bk, bi: {'key': k, 'base_kind': bk, 'base_id': bi}
ck('POSITIVE: static key on a PARAMETER object is eligible',
   eligible(R('LITERAL', 'PARAMETER', 1), asg, written, alias_src))
ck('POSITIVE: static key on a single-def LOCAL is eligible',
   eligible(R('LITERAL', 'LOCAL', 10), asg, written, alias_src))
ck('NEGATIVE: DYNAMIC key is rejected',
   not eligible(R('DYNAMIC', 'PARAMETER', 1), asg, written, alias_src))
ck('NEGATIVE: MULTI-DEF base is rejected',
   not eligible(R('LITERAL', 'LOCAL', 11), asg, written, alias_src))
ck('NEGATIVE: base object that is WRITTEN is rejected',
   not eligible(R('LITERAL', 'PARAMETER', 20), asg, written, alias_src))
ck('NEGATIVE: ALIAS to a mutable object is rejected',
   not eligible(R('LITERAL', 'LOCAL', 12), asg, written, alias_src))
ck('NEGATIVE: no-def / unknown base is rejected',
   not eligible(R('LITERAL', 'LOCAL', 99), asg, written, alias_src))
print(f'PROP_R01B_CONTROLS={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
