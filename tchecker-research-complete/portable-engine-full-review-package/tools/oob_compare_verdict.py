#!/usr/bin/env python3
"""TOR-B2a OOB_COMPARE verdict reader. THIN. Two-sided comparison-extent safety.
Consumes ONLY: READ_CMP_A / READ_CMP_B / EXTENT operand roles + cmp-capacity facts.
Emits a CANDIDATE (never 'VULNERABLE') for memcmp/strncmp/CRYPTO_memcmp when the extent
is a compile-time constant that EXCEEDS the resolved capacity of EITHER operand.

CLASS-SEPARATION INVARIANT (the whole point): a capacity bound for side A must NOT
certify side B. Safety requires  n <= cap(A) AND n <= cap(B). If either side's capacity
is unresolved, or the extent is not a compile-time constant, ABSTAIN (no candidate).
This reader reads NO write-side, source-copy, or lifetime state.
"""
import json, sys, re
from collections import defaultdict

_LIT=re.compile(r'\s*(\d+)\s*\Z')
_SIZEOF=re.compile(r'\s*sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\Z')

def _const_extent(ecode, cmp_names_to_bytes):
    """Resolve a compile-time-constant extent to a byte count, else None (abstain)."""
    if not ecode: return None
    m=_LIT.fullmatch(ecode)
    if m: return int(m.group(1))
    m=_SIZEOF.fullmatch(ecode)
    if m:
        # sizeof(operand) resolves to that operand's own byte capacity if known
        return cmp_names_to_bytes.get(m.group(1))
    return None   # non-constant (variable / arithmetic) -> abstain

def emit_candidates(fact_prefix):
    d=json.load(open(fact_prefix))
    fns={f['id']:f.get('name') for f in d.get('functions',[])}
    calls={c['id']:c for c in d['calls']}
    roles=json.load(open(fact_prefix+'.operandrole.json'))['operand_roles']
    cmp=json.load(open(fact_prefix+'.cmpcapacity.json'))['cmp_capacities']
    op=defaultdict(dict)
    for r in roles: op[r['id']][r['role']]=r
    capA={}; capB={}; name_bytes=defaultdict(dict)
    for f in cmp:
        side=f['cmp_side']; cid=f['call_id']
        (capA if side=='READ_CMP_A' else capB)[cid]=f['capacity_bytes']
    # per-call: map operand identifier -> its byte size (for sizeof(operand) resolution)
    for cid,o in op.items():
        c=calls.get(cid)
        if not c: continue
        for role,cap in (('READ_CMP_A',capA.get(cid)),('READ_CMP_B',capB.get(cid))):
            if role in o and cap is not None:
                a=next((x for x in c.get('arguments',[]) if x['index']==o[role]['operand_index']),None)
                nm=(a or {}).get('value_ref',{}).get('code') or (a or {}).get('code')
                if nm: name_bytes[cid][nm.replace('<global>','').strip()]=cap
    candidates=[]
    for cid,o in op.items():
        if 'EXTENT' not in o or 'READ_CMP_A' not in o or 'READ_CMP_B' not in o: continue
        c=calls.get(cid)
        if not c: continue
        A=capA.get(cid); B=capB.get(cid)
        if A is None or B is None: continue          # a side unresolved -> ABSTAIN
        ea=next((a for a in c.get('arguments',[]) if a['index']==o['EXTENT']['operand_index']),None)
        ecode=(ea or {}).get('value_ref',{}).get('code') or (ea or {}).get('code')
        n=_const_extent(ecode, name_bytes.get(cid,{}))
        if n is None: continue                        # non-constant extent -> ABSTAIN
        if n<=A and n<=B: continue                    # two-sided safe -> no candidate
        # extent exceeds at least one side
        over=[s for s,cap in (('A',A),('B',B)) if n>cap]
        candidates.append({'verdict':'CANDIDATE','class':'OOB_COMPARE',
            'function':fns.get(c.get('enclosing_function_id')),'line':c.get('line'),
            'call':c['name'],'extent_bytes':n,'cap_A':A,'cap_B':B,'overruns':over,
            'site_id':f"{fns.get(c.get('enclosing_function_id'))}:{c.get('line')}:{c['name'].split('.')[-1]}"})
    return candidates

if __name__=='__main__':
    pref=sys.argv[1] if len(sys.argv)>1 else '/tmp/cmp_scan/p3.json'
    cands=emit_candidates(pref)
    print(f"OOB_COMPARE CANDIDATES: {len(cands)}")
    for c in sorted(cands,key=lambda x:x['site_id']):
        print(f"  CANDIDATE OOB_COMPARE  {c['site_id']}  n={c['extent_bytes']} "
              f"capA={c['cap_A']} capB={c['cap_B']} overruns={c['overruns']}")
