#!/usr/bin/env python3
"""HOF-R01: characterize higher-order (callback) dispatch by the PROVENANCE OF THE
CALLABLE VALUE — the JS/TS analogue of the C++ identity problem. Measure only."""
import json, sys
from collections import Counter, defaultdict
d = json.load(open(sys.argv[1]))
fns = {f['id']: f for f in d['functions']}
calls = {c['id']: c for c in d['calls']}
locals_ = {l['id']: l for l in d.get('locals', [])}
assigns = defaultdict(list)
for a in d.get('assignments', []): assigns[a['target_local_id']].append(a)
params = {}
for f in d['functions']:
    for p in f.get('parameters', []): params[p['id']] = (f['id'], p['name'], p['index'])
try:
    caps = {c['inner_local_id']: c for c in json.load(open(sys.argv[2]))['captures']} if len(sys.argv) > 2 else {}
except Exception:
    caps = {}
cat = Counter(); ex = defaultdict(list); tot = 0
for c in d['calls']:
    if c.get('resolution') in ('EXACT',): continue
    name = c.get('name') or ''
    if not name or name.startswith('<operator>'): continue
    enc = fns.get(c['enclosing_function_id'])
    if not enc: continue
    # is the callee name a PARAMETER or LOCAL of the enclosing function? -> higher-order
    pnames = {p['name']: p for p in enc.get('parameters', [])}
    lnames = {l['name']: l for l in d.get('locals', []) if l['method_id'] == enc['id']}
    if name in pnames:
        tot += 1
        cat['DIRECT_FUNCTION_PARAMETER (callee is a parameter of this function)'] += 1
        ex['DIRECT_FUNCTION_PARAMETER (callee is a parameter of this function)'].append(f"{enc['name']}::{name}")
    elif name in lnames:
        tot += 1
        lid = lnames[name]['id']
        defs = assigns.get(lid, [])
        if lid in caps:
            k = 'CAPTURED_FUNCTION (callee resolves through a capture chain)'
        elif len(defs) == 1:
            v = defs[0]['value_ref']
            if v['kind'] == 'PARAMETER': k = 'LOCAL_ALIAS_OF_PARAMETER'
            elif v['kind'] == 'CALL': k = 'RETURNED_FUNCTION (from a call)'
            elif v['kind'] == 'UNKNOWN': k = 'UNKNOWN_CALLABLE_SOURCE'
            else: k = 'LOCAL_FUNCTION_VALUE'
        elif len(defs) > 1: k = 'MULTI_DEF_CALLABLE (several possible functions)'
        else: k = 'LOCAL_WITH_NO_DEFINITION'
        cat[k] += 1; ex[k].append(f"{enc['name']}::{name}")
if tot == 0:
    print('no higher-order call sites found'); sys.exit()
print(f"HOF-R01: {tot} higher-order call sites (callee is a parameter/local value)\n")
for k, v in cat.most_common():
    print(f"  {v:5d}  {100*v//tot:3d}%  {k}")
    if ex[k]: print(f"          e.g. {ex[k][0]}")
