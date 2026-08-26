#!/usr/bin/env python3
import json,sys
p=json.load(open(sys.argv[1])); cs=[c for c in p['calls'] if c['name']=='fp']
assert len(cs)==1
c=cs[0]
ok=c['resolution']!='EXACT'
print(('PASS' if ok else 'FAIL'),'dynamic singleton is never EXACT:',c['resolution'],c.get('resolution_reason'))
print('CPP_DYNAMIC_NO_HARDEN=' + ('1/1' if ok else '0/1'))
sys.exit(0 if ok else 1)
