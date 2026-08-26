#!/usr/bin/env python3
"""B4.3 BoundFact controls. Expression-anchored, side-typed. Validates against the
guarded fixed-buffer corpus if present, else asserts the source shape. The
load-bearing control is EXPRESSION IDENTITY (NC-B5, NORM-shape)."""
import json, sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent
src=(ROOT/'tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py').read_text()
ok=tot=0
def ck(n,c):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n)
# structural
ck("BoundFact schema present", 'portable-bound-facts/0.1' in src)
ck("only LT/LE relations", "'LT'" in src and "'LE'" in src and "'EQ'" not in src)
ck("no is_bounded/has_guard/safe/verdict field", not any(w in src for w in
   ("'is_bounded'","'has_guard'","'safe'","'verdict'","'vulnerability_class'")))
ck("expression identity required (id match or exact identifier code match)",
   "_lhs_vid==_extent_vid" in src)
ck("side-typed emission (DEST_CAPACITY / SOURCE_CAPACITY)",
   "'DEST_CAPACITY'" in src and "'SOURCE_CAPACITY'" in src)
ck("no generic bound side / shared capacity at eval", "'MEMORY_CAPACITY'" not in src)
# live
fx=pathlib.Path('/tmp/cap_corpus/g.json.bound.json')
if fx.exists():
    b=json.load(open(fx))['bounds']
    d=json.load(open('/tmp/cap_corpus/g.json'))
    fns={f['id']:f['name'] for f in d['functions']}
    byfn={}
    for x in b: byfn.setdefault(fns.get(x['function_id']),[]).append(x)
    ck("live NC-B5: nc_b5 (guard expr != extent expr) emits NO bound", 'nc_b5' not in byfn)
    ck("live: g_write_* are DEST_CAPACITY", all(x['bound_side']=='DEST_CAPACITY'
       for fn in ('g_write_ok','g_write_lt') for x in byfn.get(fn,[])))
    ck("live: g_read_ok is SOURCE_CAPACITY", all(x['bound_side']=='SOURCE_CAPACITY'
       for x in byfn.get('g_read_ok',[])))
    ck("live: nc_b6 emits no DEST bound", all(x['bound_side']!='DEST_CAPACITY'
       for x in byfn.get('nc_b6',[])))
    ck("live: >=1 real BoundFact emitted", len(b)>=1)
print(f"BOUND_CONTROLS={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
