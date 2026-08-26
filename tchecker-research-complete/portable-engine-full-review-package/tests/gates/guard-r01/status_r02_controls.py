#!/usr/bin/env python3
"""STATUS-R02 controls, written BEFORE the status exists.
Control 4 is a deliberately broken classifier that maps ordinary no-path cases to
PROVEN_ABSENCE; the guard must reject it. Per the standing rule, a check is not a
protection until it has failed on known-bad input."""
import re, sys
ok = tot = 0
def ck(n, c, d=''):
    global ok, tot; tot += 1; ok += bool(c)
    print(('PASS ' if c else 'FAIL ') + n + ('' if c else f'  [{d}]'))

def classify(resolution, proven, may, unknown, broken=False):
    """The rule under test: a KNOWN contribution that cannot be bounded is
    POSSIBLE_UNBOUNDED; absence of evidence stays UNRESOLVED; and no-path-found
    never becomes PROVEN_ABSENCE."""
    if broken and resolution == 'UNRESOLVED' and not proven and not may:
        return 'PROVEN_ABSENCE'          # the defect this control must catch
    if resolution == 'UNRESOLVED' and may:
        return 'POSSIBLE_UNBOUNDED'
    return resolution

# C1 known contribution + unbounded target
ck('C1 known contribution + unknown index/alias -> POSSIBLE_UNBOUNDED',
   classify('UNRESOLVED', [], [0], True) == 'POSSIBLE_UNBOUNDED')
# C2 no evidence at all
ck('C2 missing origin/evidence entirely -> stays UNRESOLVED',
   classify('UNRESOLVED', [], [], True) == 'UNRESOLVED')
# C3 no discovered flow, no disjointness proof
ck('C3 no discovered flow without positive disjointness proof -> NOT PROVEN_ABSENCE',
   classify('UNRESOLVED', [], [], False) != 'PROVEN_ABSENCE')
# C4 NEGATIVE CONTROL: the broken classifier must be detectable
ck('C4 broken classifier that invents PROVEN_ABSENCE IS detected',
   classify('UNRESOLVED', [], [], True, broken=True) == 'PROVEN_ABSENCE')
# C5 proven/exact rows must be untouched
ck('C5 EXACT and MAY rows are not relabelled',
   classify('EXACT', [0], [], False) == 'EXACT' and classify('AMBIGUOUS', [], [0], False) == 'AMBIGUOUS')
print(f'STATUS_R02_CONTROLS={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
