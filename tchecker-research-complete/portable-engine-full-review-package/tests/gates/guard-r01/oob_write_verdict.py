#!/usr/bin/env python3
"""B4.5 OOB_WRITE verdict reader. THIN. Consumes ONLY the write-side neutral chain:
  WRITE_DEST + EXTENT operand roles, DestinationCapacityFact, DEST_CAPACITY BoundFact.
Emits a CANDIDATE (never 'VULNERABLE') when a memory-write site is representable
(role + extent + destination capacity) AND has NO valid DEST_CAPACITY bound on the
EXACT extent value id. Creates no new semantics.

CLASS ISOLATION (portable analogue of the PHP contract): this reader must NOT read
SourceCapacityFact, SOURCE_CAPACITY bounds, or any read-side state. Enforced by
only opening the dest/role sidecars + filtering bounds to bound_side==DEST_CAPACITY.
"""
import json, sys, pathlib

def emit_candidates(fact_prefix):
    d=json.load(open(fact_prefix))
    fns={f['id']:f.get('name') for f in d.get('functions',[])}
    calls={c['id']:c for c in d['calls']}
    roles=json.load(open(fact_prefix+'.operandrole.json'))['operand_roles']
    dcap={f['storage_value_id']:f for f in json.load(open(fact_prefix+'.destcapacity.json'))['dest_capacities']}
    # ISOLATION: only DEST_CAPACITY bounds are loaded into the write reader.
    all_bounds=json.load(open(fact_prefix+'.bound.json'))['bounds']
    dest_bounds={(b['checked_value_id'],b['bound_side']) for b in all_bounds
                 if b['bound_side']=='DEST_CAPACITY'}
    op={}
    for r in roles: op.setdefault(r['id'],{})[r['role']]=r
    candidates=[]
    for cid,o in op.items():
        if 'EXTENT' not in o or 'WRITE_DEST' not in o: continue   # write site with a size
        c=calls.get(cid)
        if not c: continue
        earg=next((a for a in c.get('arguments',[]) if a['index']==o['EXTENT']['operand_index']),None)
        evid=(earg or {}).get('value_ref',{}).get('referenced_id') or (earg or {}).get('value_ref',{}).get('id')
        darg=next((a for a in c.get('arguments',[]) if a['index']==o['WRITE_DEST']['operand_index']),None)
        dvid=(darg or {}).get('value_ref',{}).get('referenced_id') or (darg or {}).get('value_ref',{}).get('id')
        if evid is None or dvid not in dcap: continue             # not representable -> abstain
        # representable. is there a VALID dest bound on the EXACT extent id?
        if (evid,'DEST_CAPACITY') in dest_bounds: continue        # validly bounded -> no candidate
        candidates.append({'verdict':'CANDIDATE','class':'OOB_WRITE',
            'function':fns.get(c.get('enclosing_function_id')),'line':c.get('line'),
            'call':c['name'],'extent_value_id':evid,
            'dest_capacity_bytes':dcap[dvid]['capacity_bytes'],
            'site_id':f"{fns.get(c.get('enclosing_function_id'))}:{c.get('line')}:{c['name']}"})
    return candidates

if __name__=='__main__':
    pref=sys.argv[1] if len(sys.argv)>1 else '/tmp/cap_corpus/g.json'
    cands=emit_candidates(pref)
    print(f"OOB_WRITE CANDIDATES: {len(cands)}")
    for c in sorted(cands,key=lambda x:x['site_id']):
        print(f"  CANDIDATE OOB_WRITE  {c['site_id']}  dest_cap={c['dest_capacity_bytes']}B")
