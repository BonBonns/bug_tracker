#!/usr/bin/env python3
"""B4.6 OOB_READ verdict reader. THIN. Physical mirror of the OOB_WRITE reader.
Consumes ONLY the read-side neutral chain:
  READ_SRC + EXTENT operand roles, SourceCapacityFact, SOURCE_CAPACITY BoundFact.
Emits CANDIDATE (never 'VULNERABLE') when a read site is representable (role +
extent + source capacity) AND has NO valid SOURCE_CAPACITY bound on the EXACT
extent value id. Creates no new semantics.

CLASS ISOLATION: must NOT read DestinationCapacityFact, DEST_CAPACITY bounds, or
any write-side state. Enforced: destcapacity file never opened; bounds filtered to
bound_side=='SOURCE_CAPACITY'. Separate verdict channel from OOB_WRITE.
"""
import json, sys, pathlib

def emit_candidates(fact_prefix):
    d=json.load(open(fact_prefix))
    fns={f['id']:f.get('name') for f in d.get('functions',[])}
    calls={c['id']:c for c in d['calls']}
    roles=json.load(open(fact_prefix+'.operandrole.json'))['operand_roles']
    scap={f['storage_value_id']:f for f in json.load(open(fact_prefix+'.srccapacity.json'))['src_capacities']}
    # ISOLATION: only SOURCE_CAPACITY bounds enter the read reader.
    all_bounds=json.load(open(fact_prefix+'.bound.json'))['bounds']
    src_bounds={(b['checked_value_id'],b['bound_side']) for b in all_bounds
                if b['bound_side']=='SOURCE_CAPACITY'}
    op={}
    for r in roles: op.setdefault(r['id'],{})[r['role']]=r
    candidates=[]
    for cid,o in op.items():
        if 'EXTENT' not in o or 'READ_SRC' not in o: continue     # read site with a size
        c=calls.get(cid)
        if not c: continue
        earg=next((a for a in c.get('arguments',[]) if a['index']==o['EXTENT']['operand_index']),None)
        evid=(earg or {}).get('value_ref',{}).get('referenced_id') or (earg or {}).get('value_ref',{}).get('id')
        sarg=next((a for a in c.get('arguments',[]) if a['index']==o['READ_SRC']['operand_index']),None)
        svid=(sarg or {}).get('value_ref',{}).get('referenced_id') or (sarg or {}).get('value_ref',{}).get('id')
        if evid is None or svid not in scap: continue             # not representable -> abstain
        if (evid,'SOURCE_CAPACITY') in src_bounds: continue       # validly bounded -> no candidate
        candidates.append({'verdict':'CANDIDATE','class':'OOB_READ',
            'function':fns.get(c.get('enclosing_function_id')),'line':c.get('line'),
            'call':c['name'],'extent_value_id':evid,
            'src_capacity_bytes':scap[svid]['capacity_bytes'],
            'site_id':f"{fns.get(c.get('enclosing_function_id'))}:{c.get('line')}:{c['name']}"})
    return candidates

if __name__=='__main__':
    pref=sys.argv[1] if len(sys.argv)>1 else '/tmp/cap_corpus/g.json'
    cands=emit_candidates(pref)
    print(f"OOB_READ CANDIDATES: {len(cands)}")
    for c in sorted(cands,key=lambda x:x['site_id']):
        print(f"  CANDIDATE OOB_READ  {c['site_id']}  src_cap={c['src_capacity_bytes']}B")
