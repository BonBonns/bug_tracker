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
import json, sys, pathlib, re

# B4.7 STATIC_EXTENT_SAFE — a provenance-DISTINCT safety reason (NOT a BoundFact).
# A write is statically safe when the extent expression is EXACTLY sizeof(D) and D is
# the SAME identifier as the write destination. This is compile-time evidence
# (E == capacity(D) mathematically), architecturally separate from guard-derived
# BoundFacts (control-flow evidence). Kept narrow by five conjoined conditions so it
# cannot suppress the real teeth cases:
#   - sizeof(other_buffer)  -> name mismatch -> NOT safe (stays candidate)
#   - sizeof(pointer)       -> pointer has no resolved capacity -> never reaches here
#   - sizeof(dst)+1         -> not a pure sizeof() (fullmatch fails) -> NOT safe
#   - variable extent n     -> not sizeof -> NOT safe
_SIZEOF_RE = re.compile(r'\s*sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\Z')
def _dest_ident(code):
    return (code or '').replace('<global>', '').strip()
def is_static_extent_safe(dest_code, ext_code):
    m = _SIZEOF_RE.fullmatch(ext_code or '')
    if not m:
        return False                          # not a pure sizeof(X) -> not statically safe
    return m.group(1) == _dest_ident(dest_code)  # must be sizeof of the EXACT destination

def emit_candidates(fact_prefix):
    d=json.load(open(fact_prefix))
    fns={f['id']:f.get('name') for f in d.get('functions',[])}
    calls={c['id']:c for c in d['calls']}
    roles=json.load(open(fact_prefix+'.operandrole.json'))['operand_roles']
    _dest_facts=json.load(open(fact_prefix+'.destcapacity.json'))['dest_capacities']
    # CAP-KEY-R01: join capacity to an operand by EXPLICIT identity kind, never by a sentinel
    # storage id. A field access collapses storage_value_id to -1; -1 is NEVER a valid join key.
    # VALUE_ID facts join by storage_value_id (>=0). FIELD facts join by call_id (unique per
    # site) + field_storage_key, so distinct members at the same -1 never collide.
    dcap={}                       # storage_value_id -> fact  (VALUE_ID only, sid>=0)
    dcap_by_call={}               # call_id -> fact           (FIELD facts)
    for f in _dest_facts:
        kind=f.get('storage_identity_kind','VALUE_ID')
        if kind=='FIELD':
            dcap_by_call[f['call_id']]=f
        else:
            sid=f['storage_value_id']
            if sid is not None and sid>=0:      # sentinel/negative ids are not joinable
                dcap[sid]=f
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
        # resolve capacity by identity kind: VALUE_ID by sid (>=0), FIELD by call_id.
        _capfact=None
        if dvid is not None and dvid>=0 and dvid in dcap:
            _capfact=dcap[dvid]
        elif cid in dcap_by_call:
            _capfact=dcap_by_call[cid]           # field fact for THIS site
        if evid is None or _capfact is None: continue             # not representable -> abstain
        # STATIC_EXTENT_SAFE: extent is exactly sizeof(the destination) -> compile-time safe.
        # Provenance-distinct from bounds; uses only this site's own extent+dest code.
        ext_code=(earg or {}).get('value_ref',{}).get('code')
        dest_code=(darg or {}).get('value_ref',{}).get('code')
        if is_static_extent_safe(dest_code, ext_code): continue   # statically safe -> no candidate
        # representable. is there a VALID dest bound on the EXACT extent id?
        if (evid,'DEST_CAPACITY') in dest_bounds: continue        # validly bounded -> no candidate
        candidates.append({'verdict':'CANDIDATE','class':'OOB_WRITE',
            'function':fns.get(c.get('enclosing_function_id')),'line':c.get('line'),
            'call':c['name'],'extent_value_id':evid,
            'dest_capacity_bytes':_capfact['capacity_bytes'],
            'site_id':f"{fns.get(c.get('enclosing_function_id'))}:{c.get('line')}:{c['name']}"})
    return candidates

if __name__=='__main__':
    pref=sys.argv[1] if len(sys.argv)>1 else '/tmp/cap_corpus/g.json'
    cands=emit_candidates(pref)
    print(f"OOB_WRITE CANDIDATES: {len(cands)}")
    for c in sorted(cands,key=lambda x:x['site_id']):
        print(f"  CANDIDATE OOB_WRITE  {c['site_id']}  dest_cap={c['dest_capacity_bytes']}B")
