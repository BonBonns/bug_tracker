#!/usr/bin/env python3
"""SINK-R01: provenance observed at call-argument positions must use the SAME
vocabulary and the same calibration as the return query."""
import re, sys
out = open(sys.argv[1]).read()
ok = tot = 0
def ck(n, c, d=''):
    global ok, tot; tot += 1; ok += bool(c)
    print(('PASS ' if c else 'FAIL ') + n + ('' if c else f'  [{d}]'))
def sink(fn, idx):
    m = re.search(rf'SINK {fn} \S+#{idx} resolution=(\S+) proven=\[([^\]]*)\] may=\[([^\]]*)\] unknown=(\S+)', out)
    if not m: return None
    n = lambda x: sorted(int(v) for v in x.split(',') if v.strip())
    return m.group(1), n(m.group(2)), n(m.group(3)), m.group(4) == 'true'
ck('s1 arg0: definite parameter flow into the sink -> EXACT[0]', sink('s1', 0) == ('EXACT', [0], [], False), sink('s1', 0))
ck('s1 arg1: constant argument makes no value-origin claim',
   sink('s1', 1) and not sink('s1', 1)[1] and not sink('s1', 1)[2], sink('s1', 1))
r = sink('s2', 1)
ck('s2 arg1: known contribution, unbounded -> POSSIBLE_UNBOUNDED may={0}',
   r and r[0] == 'POSSIBLE_UNBOUNDED' and r[2] == [0], r)
r = sink('s3', 0)
ck('s3 arg0: bounded two-origin set -> AMBIGUOUS may={0,1}',
   r and r[0] == 'AMBIGUOUS' and r[2] == [0, 1], r)
r = sink('s4', 0)
ck('s4 arg0: unknown index -> UNRESOLVED, no origin claimed',
   r and r[0] == 'UNRESOLVED' and not r[1] and not r[2], r)
r = sink('s5', 0)
ck('s5 arg0: constant sink argument makes no value-origin claim',
   r and not r[1] and not r[2], r)
print(f'SINK_R01={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
