#!/usr/bin/env python3
"""Controls for the R03 recoverability test. It must flip in BOTH directions,
per cause — otherwise the yield table is another default in disguise."""
import re, subprocess, sys
out=subprocess.run(['python3','ts_unresolved_r01.py'],capture_output=True,text=True).stdout
rows=[]
for l in out.splitlines():
    m=re.match(r"\s+ROW (\S+):(\S+) (\S+) -> \[(.*?)\] recoverable=(True|False)",l)
    if m: rows.append((m.group(1),m.group(2),m.group(3),m.group(4),m.group(5)=='True'))
ok=tot=0
def ck(n,c,d=''):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n+('' if c else f'  [{d}]'))
def has(cause,val):
    return any(cause in r[3] and r[4]==val for r in rows)
ck('POSITIVE control: some EXTERNAL_CALL is recoverable-alone', has('EXTERNAL_CALL',True))
ck('NEGATIVE control: some EXTERNAL_CALL is downstream-blocked', has('EXTERNAL_CALL',False))
ck('POSITIVE control: some OBJECT_PROPERTY_READ is recoverable-alone', has('OBJECT_PROPERTY_READ',True))
ck('NEGATIVE control: some OBJECT_PROPERTY_READ is downstream-blocked', has('OBJECT_PROPERTY_READ',False))
# the metric must not be constant
vals={r[4] for r in rows}
ck('metric is not constant across instances', len(vals)==2, vals)
print(f'TS_RECOVERABILITY_CONTROLS={ok}/{tot}')
sys.exit(0 if ok==tot else 1)
