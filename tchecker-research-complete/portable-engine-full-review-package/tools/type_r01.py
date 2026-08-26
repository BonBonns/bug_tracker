#!/usr/bin/env python3
"""TYPE-R01: characterize WHY argument types are ANY, before inventing inference.
Splits the INSUFFICIENT_TYPE_INFO rows by where the missing type originates."""
import json, sys
from collections import Counter, defaultdict
d=json.load(open(sys.argv[1]))
fns={f['id']:f for f in d['functions']}
calls={c['id']:c for c in d['calls']}
bodied=set()
for c in d['calls']: bodied.add(c['enclosing_function_id'])
for l in d.get('locals',[]): bodied.add(l['method_id'])
for r in d.get('returns',[]): bodied.add(r['function_id'])
own=lambda f: not (f.get('full_name','') or '').startswith(('std.','__gnu_cxx','__','operator')) and not f['name'].startswith('_')
defs=defaultdict(list)
for f in d['functions']:
    if f.get('is_external') or f['id'] not in bodied or not f.get('line') or not own(f): continue
    defs[f['name']].append(f)
cat=Counter(); ex=defaultdict(list)
for c in d['calls']:
    n=c['name']
    if not n or n.startswith(('<','_')) or n in ('ANY','void'): continue
    e=fns.get(c['enclosing_function_id'])
    if not e or not own(e): continue
    if [t for t in c.get('candidate_target_ids',[]) if t in fns and not fns[t].get('is_external')]: continue
    if not defs.get(n): continue
    args=c.get('arguments',[])
    if not args: continue
    types=[(a.get('type_full_name') or '').strip() for a in args]
    if not all(t in ('ANY','','__type') for t in types): continue
    # classify origin of the missing type
    kinds={a.get('kind') for a in args}
    codes=' '.join((a.get('code') or '')[:30] for a in args)
    cand=defs[n][0]
    params=cand.get('parameters',[])
    ptypes=[(p.get('type_full_name') or '') for p in params]
    if params and all(t in ('ANY','') for t in ptypes):
        k='PARAM_TYPE_MISSING_ON_CANDIDATE'
    elif any(a.get('kind')=='CALL' for a in args):
        k='ARG_IS_CALL_RESULT (return type unknown)'
    elif any('<' in (a.get('code') or '') and '>' in (a.get('code') or '') for a in args):
        k='TEMPLATE_INSTANTIATION_LOSS'
    elif any((a.get('code') or '').startswith(('&','*')) for a in args):
        k='POINTER/REFERENCE_DECAY'
    elif any((a.get('code') or '').replace('.','').replace('-','').isdigit() or
             (a.get('code') or '').startswith(('"',"'")) for a in args):
        k='LITERAL/CONVERSION_CASE'
    elif 'IDENTIFIER' in kinds:
        k='ARG_EXPRESSION_IS_ANY (identifier with no type)'
    else:
        k='OTHER'
    cat[k]+=1; ex[k].append(f"{n}({codes[:34]})")
tot=sum(cat.values())
print(f"TYPE-R01: {tot} INSUFFICIENT_TYPE_INFO calls classified by ORIGIN of the missing type\n")
for k,v in cat.most_common():
    print(f"  {v:5d}  {100*v//tot if tot else 0:3d}%  {k}")
    print(f"          e.g. {ex[k][0]}")
