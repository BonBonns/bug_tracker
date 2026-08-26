#!/usr/bin/env python3
"""JSTS-R09: repo-scale refresh after first-class FUNCTION references."""
import json, subprocess, sys, os, re
from collections import defaultdict
rows=[]
for tag, work, rep in [x.split(':') for x in sys.argv[1:]]:
    try:
        s=json.load(open(rep))['sides'][0]
        d=json.load(open(f'{work}/js.json'))
    except Exception as e:
        rows.append((tag,'—','—','—','—','—','—','—','—')); continue
    fns={f['id']:f for f in d['functions']}
    bodied=set()
    for c in d['calls']: bodied.add(c['enclosing_function_id'])
    for r in d.get('returns',[]): bodied.add(r['function_id'])
    file_of={f['id']:(f.get('file') or '') for f in d['functions']}
    byname=defaultdict(list)
    for f in d['functions']:
        if not f.get('is_external') and f['id'] in bodied: byname[f['name']].append(f)
    exact=[c for c in d['calls'] if c.get('resolution')=='EXACT' and len(c.get('candidate_target_ids',[]))==1]
    crossfile=[c for c in exact if file_of.get(c['candidate_target_ids'][0])!=file_of.get(c['enclosing_function_id'])]
    amb=sum(1 for k,v in byname.items() if len(v)>1)
    out=subprocess.run(['python3','hof_r02.py',work,tag],capture_output=True,text=True).stdout
    g=lambda k: int(re.search(rf'(\d+)\s+\d+%\s+{re.escape(k)}',out).group(1)) if re.search(rf'(\d+)\s+\d+%\s+{re.escape(k)}',out) else 0
    rows.append((tag, s['functions_analyzed'], s['proven_flows'], s['abstained'],
                 len(exact), g('EXACT_CALLABLE'), g('BOUNDED_CALLABLE_SET'),
                 g('UNKNOWN_CALLABLE'), g('EXTERNAL_CALLABLE'), len(crossfile), amb))
hdr=('repo','analyzed','proven','abstain','EXACTdisp','EXACTcallable','bounded','unknownC','externalC','xfileEXACT','ambigNames')
print(f"{hdr[0]:14s}"+"".join(f"{h:>13s}" for h in hdr[1:]))
for r in rows:
    print(f"{r[0]:14s}"+"".join(f"{str(x):>13s}" for x in r[1:]))
