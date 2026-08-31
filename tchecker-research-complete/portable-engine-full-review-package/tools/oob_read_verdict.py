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
import json, sys, pathlib, re

# B4.7R STATIC_EXTENT_SAFE (task #43) -- read-side mirror of oob_write_verdict.py's B4.7
# STATIC_EXTENT_SAFE. A provenance-DISTINCT safety reason (NOT a BoundFact): a read is
# statically safe when the extent is compile-time-provably <= the source's own capacity,
# independent of any control-flow guard. Two conjoined-narrow forms, so this cannot suppress
# real teeth cases:
#   1. extent is EXACTLY sizeof(S) and S is the SAME identifier as the read source -- symmetric
#      to the write side's sizeof(dest) case. E == capacity(S) mathematically.
#   2. extent is a compile-time integer LITERAL and the source's own capacity_bytes is a known
#      compile-time integer -- safe iff literal <= capacity. Concretely motivated by a real re2
#      site (#29/#43): memcpy(out, spec->expstr, 4) with a real capacity_bytes=5 for spec->expstr
#      -- 4<=5 is statically safe, yet the scanner reported it as verdict=CANDIDATE before this
#      fix. Conservative: anything that is not a clean decimal literal of exactly this argument
#      (an expression, a macro, a variable, a negative/hex/suffixed literal) does NOT match and
#      stays a CANDIDATE -- no new false negatives.
_SIZEOF_RE = re.compile(r'\s*sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\Z')
_INT_LITERAL_RE = re.compile(r'\s*(\d+)\s*\Z')
def _src_ident(code):
    return (code or '').replace('<global>', '').strip()
def is_static_extent_safe(src_code, ext_code, ext_kind, capacity_bytes):
    m = _SIZEOF_RE.fullmatch(ext_code or '')
    if m and m.group(1) == _src_ident(src_code):
        return True
    lm = _INT_LITERAL_RE.fullmatch(ext_code or '')
    if lm and ext_kind == 'LITERAL' and isinstance(capacity_bytes, int):
        return int(lm.group(1)) <= capacity_bytes
    return False

def emit_candidates(fact_prefix):
    d=json.load(open(fact_prefix))
    fns={f['id']:f.get('name') for f in d.get('functions',[])}
    calls={c['id']:c for c in d['calls']}
    roles=json.load(open(fact_prefix+'.operandrole.json'))['operand_roles']
    _src_facts=json.load(open(fact_prefix+'.srccapacity.json'))['src_capacities']
    # CAP-KEY-R01 (task #29): join capacity to an operand by EXPLICIT identity kind, never
    # by a sentinel storage id. A field access collapses storage_value_id to -1; -1 is NEVER
    # a valid join key -- treating it as one made every read site whose own field-identity
    # resolution failed (svid==-1) spuriously collide on whichever ONE unrelated FIELD fact
    # happened to exist in the package (observed: a uniform, bogus src_capacity_bytes=5
    # borrowed from an unrelated struct member, on 6 of 7 real re2 candidates). Mirrors the
    # dcap/dcap_by_call split already correct in oob_write_verdict.py. VALUE_ID facts join
    # by storage_value_id (>=0). FIELD facts join by call_id (unique per site).
    scap={}                       # storage_value_id -> fact  (VALUE_ID only, sid>=0)
    scap_by_call={}               # call_id -> fact           (FIELD facts)
    for f in _src_facts:
        kind=f.get('storage_identity_kind','VALUE_ID')
        if kind=='FIELD':
            scap_by_call[f['call_id']]=f
        else:
            sid=f['storage_value_id']
            if sid is not None and sid>=0:      # sentinel/negative ids are not joinable
                scap[sid]=f
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
        # resolve capacity by identity kind: VALUE_ID by sid (>=0), FIELD by call_id.
        _capfact=None
        if svid is not None and svid>=0 and svid in scap:
            _capfact=scap[svid]
        elif cid in scap_by_call:
            _capfact=scap_by_call[cid]           # field fact for THIS site
        if evid is None or _capfact is None: continue             # not representable -> abstain
        # STATIC_EXTENT_SAFE (task #43): extent is compile-time-provably within the source's own
        # capacity -> statically safe, not a candidate. Provenance-distinct from bounds; uses only
        # this site's own extent+source code and the already-resolved capacity fact.
        ext_code=(earg or {}).get('value_ref',{}).get('code')
        ext_kind=(earg or {}).get('kind')
        src_code=(sarg or {}).get('value_ref',{}).get('code')
        if is_static_extent_safe(src_code, ext_code, ext_kind, _capfact['capacity_bytes']): continue
        if (evid,'SOURCE_CAPACITY') in src_bounds: continue       # validly bounded -> no candidate
        candidates.append({'verdict':'CANDIDATE','class':'OOB_READ',
            'function':fns.get(c.get('enclosing_function_id')),'line':c.get('line'),
            'call':c['name'],'extent_value_id':evid,
            'src_capacity_bytes':_capfact['capacity_bytes'],
            # PROV-R01: additive orchestrator-only join keys, see oob_write_verdict.py.
            'call_id':c['id'],'function_id':c.get('enclosing_function_id'),
            'site_id':f"{fns.get(c.get('enclosing_function_id'))}:{c.get('line')}:{c['name']}"})
    return candidates

if __name__=='__main__':
    pref=sys.argv[1] if len(sys.argv)>1 else '/tmp/cap_corpus/g.json'
    cands=emit_candidates(pref)
    print(f"OOB_READ CANDIDATES: {len(cands)}")
    for c in sorted(cands,key=lambda x:x['site_id']):
        print(f"  CANDIDATE OOB_READ  {c['site_id']}  src_cap={c['src_capacity_bytes']}B")
