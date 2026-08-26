#!/usr/bin/env python3
"""OOB-INDEX-R01 gate. Frozen fixtures; runs oob_index_write_verdict unchanged.
Asserts the vuln/patched/safe control matrix that gated this capability."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oiw", H/"oob_index_write_verdict.py")
oiw = importlib.util.module_from_spec(spec); spec.loader.exec_module(oiw)
def cands(fx): return oiw.emit_candidates(str(H/"fixtures"/fx))
ok=tot=0
def ck(name, cond):
    global ok,tot; tot+=1; ok+=bool(cond); print(("PASS " if cond else "FAIL ")+name)

# CONTROLS (one file, 4 functions): exactly bad_unbounded flags
c = cands("controls.program.json"); flagged = {x['array']+'@'+str(x['function_id']) for x in c}
ck("controls: exactly 1 candidate", len(c)==1)
ck("controls: the flagged write is rg[c] in bad_unbounded (unbounded)", len(c)==1 and c[0]['array']=='rg' and c[0]['index_expr']=='c')
# ROW 3 positive control: vuln flags, patched suppresses
v=cands("row3_vuln.program.json"); f=cands("row3_fixed.program.json")
ck("row3 VULN (CVE-2022-28281) FLAGS rgExtension[cExtensions]", len(v)==1 and v[0]['array']=='rgExtension')
ck("row3 FIXED suppressed (real sizeof guard credited, MOZ_ASSERT ignored)", len(f)==0)
# no false positives on the other-shape rows
ck("row1 (libtremor, pointer-param) no FP", len(cands("row1_vuln.program.json"))==0)
ck("row2 (WebGL memcpy read) no FP", len(cands("row2_readsite.program.json"))==0)
# CAPACITY SCOPING regression (found scanning real mozilla/nss lib/freebl/mpi.c: mp_gcd's own
# `mp_int *clear[3]` was reported with capacity 6, borrowed from an unrelated same-named
# `mp_int *clear[6]` local in a different function, s_mp_invmod_odd_m, elsewhere in the same
# file). Two functions declaring a same-named fixed array with DIFFERENT capacities must each
# get their own, not whichever's local was last in file order.
s = cands("same_name_diff_capacity.program.json")
by_fn = {x['function_id']: x for x in s}
ck("same-name capacity: 2 candidates (one per function)", len(s) == 2)
ck("same-name capacity: fn_small's sh[] keeps its own capacity 3 (not borrowed 9)",
   by_fn.get(900000000001, {}).get('elem_count') == 3)
ck("same-name capacity: fn_big's sh[] keeps its own capacity 9 (not borrowed 3)",
   by_fn.get(900000000002, {}).get('elem_count') == 9)
print(f"OOB_INDEX_R01={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
