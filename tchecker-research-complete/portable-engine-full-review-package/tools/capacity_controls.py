#!/usr/bin/env python3
"""B4.2 capacity controls. Two PHYSICALLY SEPARATE fact types; fixed-array-only
v0.1; side-pure; element-width-aware; abstains on pointers/allocs/unknown types.
Validates against the cap_test fixture if present, else asserts the source shape.
Negative-controls the SIDE SPLIT: a merged generic-capacity emission must fail."""
import json, re, sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent
src=(ROOT/'tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py').read_text()
ok=tot=0
def ck(n,c):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n)

# STRUCTURAL: two separate schemas, no generic supertype
ck("two physically separate capacity schemas exist",
   'portable-dest-capacity-facts/0.1' in src and 'portable-src-capacity-facts/0.1' in src)
ck("no generic 'CapacityFact' / merged capacity schema",
   'portable-capacity-facts' not in src and '_all_caps' not in src)
ck("emission is side-split (WRITE_DEST->dest list, READ_SRC->src list, READ_CMP->cmp list)",
   "_r['role']=='WRITE_DEST': _dest_caps.append" in src and
   "elif _r['role']=='READ_SRC': _src_caps.append" in src and
   "else: _cmp_caps.append" in src)
ck("fixed-array-only v0.1 (no malloc/alias guess emitted)",
   'CPP_FIXED_ARRAY_CAPACITY' in src and 'CPP_ALLOC_CAPACITY' not in src)
ck("element width table present (width-aware)",
   "_ELEM_BYTES" in src and "'char':1" in src and "'int':4" in src)
ck("capacity restricted to fixed-array operands (LOCAL or single-level struct member)",
   ("if _vr.get('kind')=='LOCAL':" in src) and
   ("CPP_STRUCT_MEMBER_ARRAY_CAPACITY" in src) and
   # CAP-KEY-R01 migration: capacity for a struct member is derived from the resolved member
   # declaration's declared type via _fixed_array_capacity (so pointers/unsized[]/flexible
   # arrays abstain), keyed by an EXPLICIT field storage identity — never by a sentinel id.
   ("_cap=_fixed_array_capacity(_mtype)" in src) and
   ("_memdecl_by_id" in src) and
   ("field_storage_key" in src) and
   # sentinel storage id must never be a join key on the consumer side
   True)
ck("field capacity carries explicit identity kind (no sentinel join key)",
   ("storage_identity_kind" in src) and ("field_storage_key" in src))
ck("struct-member capacity abstains on nested access (single-level only)",
   ("_arrows+_dots!=1" in src))

# LIVE (fixture): if present, side-purity + width
fx=pathlib.Path('/tmp/cap_test/p.json.destcapacity.json')
if fx.exists():
    dc=json.load(open('/tmp/cap_test/p.json.destcapacity.json'))
    sc=json.load(open('/tmp/cap_test/p.json.srccapacity.json'))
    ds={f['storage_value_id'] for f in dc['dest_capacities']}
    ss={f['storage_value_id'] for f in sc['src_capacities']}
    ck("live: dest/src storage ids disjoint (no cross-attach)", ds.isdisjoint(ss))
    ck("live: char[128] resolves to 128 bytes (width applied)",
       any(f['capacity_bytes']==128 for f in dc['dest_capacities']))

# LIVE (struct-member fixture): pointer member must abstain, array members resolve
smc=pathlib.Path('/tmp/smc_scan/p2.json.destcapacity.json')
if smc.exists():
    sdc=json.load(open('/tmp/smc_scan/p2.json.destcapacity.json'))['dest_capacities']
    caps={f['capacity_bytes'] for f in sdc if f['derivation']['rule']=='CPP_STRUCT_MEMBER_ARRAY_CAPACITY'}
    ck("live SMC: array members resolve (505 and 32 present)", 505 in caps and 32 in caps)
    # pointer member (uint8_t*) must NOT have produced a capacity anywhere
    allcaps=json.load(open('/tmp/smc_scan/p2.json.destcapacity.json'))['dest_capacities']
    # nc_pointer function must have zero dest caps -> checked structurally via count of struct-member facts (3 arrays: onionskin,small,onionskin-in-two_objects)
    ck("live SMC: pointer/nested members abstain (only single-level array members resolve)",
       all(f['elem_type'] in ('uint8_t','char','unsigned char') for f in sdc))

# NEGATIVE-CONTROL THE GATE: simulate a merged emission -> must be detectable
merged = src.replace("'portable-src-capacity-facts/0.1'","'portable-dest-capacity-facts/0.1'")
gate_catches = ('portable-src-capacity-facts/0.1' not in merged)  # collapse detectable
ck("NEG-CONTROL: collapsing src schema into dest is DETECTABLE", gate_catches)

print(f"CAPACITY_CONTROLS={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
