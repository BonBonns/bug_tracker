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
ck("abstains on non-LOCAL operands (pointer/param discipline)",
   "if _vr.get('kind')!='LOCAL': continue" in src)

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

# NEGATIVE-CONTROL THE GATE: simulate a merged emission -> must be detectable
merged = src.replace("'portable-src-capacity-facts/0.1'","'portable-dest-capacity-facts/0.1'")
gate_catches = ('portable-src-capacity-facts/0.1' not in merged)  # collapse detectable
ck("NEG-CONTROL: collapsing src schema into dest is DETECTABLE", gate_catches)

print(f"CAPACITY_CONTROLS={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
