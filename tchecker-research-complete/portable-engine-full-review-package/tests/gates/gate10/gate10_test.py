#!/usr/bin/env python3
import json,sys
p=sys.argv[1]
d=json.load(open(p))
expect={
 'topState':['PARAM:topState.source'],
 'topConstantOverwrite':['CONST:"CONST"'],
 'directState':['PARAM:directState.source'],
 'directConstant':['CONST:"CONST"'],
 'sameObject':['PARAM:sameObject.source'],
}
fail=[]
for k,v in expect.items():
    got=d[k]['origins']; ok=got==v
    print(('PASS' if ok else 'FAIL'),k,'=>',got)
    if not ok: fail.append(k)
# Negative controls: no source flow.
for k in ['differentField','twoObjects']:
    got=d[k]['origins']; bad=any(x.endswith('.source') or '.source' in x for x in got)
    print(('PASS' if not bad else 'FAIL'),k,'=>',got,'(no source flow expected)')
    if bad: fail.append(k)
print(f'GATE10={7-len(fail)}/7')
raise SystemExit(1 if fail else 0)
