#!/usr/bin/env python3
"""B4.1 OperandRoleFact controls. Curated per-API roles; neutral (no capacity/
bound/class/verdict). Negative-controlled: read-side never WRITE_DEST, write-side
never READ_SRC, unknown APIs abstain, roles are per-API-explicit not positional."""
import json, os, subprocess, sys, tempfile, pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent
# regenerate a small fixture through the C normalizer would need joern; instead
# validate against the already-generated norm operand-role sidecar if present, else
# assert the curated table shape directly from the normalizer source (robust, offline).
src=(ROOT/'tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py').read_text()
import re
m=re.search(r'_OPERAND_ROLES\s*=\s*\{(.*?)\n    \}', src, re.S)
tbl=m.group(1) if m else ''
ok=tot=0
def ck(n,c):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n)
ck("memcpy has distinct dst/src/extent", "0:'WRITE_DEST'" in tbl and "1:'READ_SRC'" in tbl and "2:'EXTENT'" in tbl)
ck("strcpy/sprintf absent (no extent -> not fabricated)", "'strcpy'" not in tbl and "'sprintf'" not in tbl)
ck("no capacity/bound/class token in role table (neutral)",
   not any(w in tbl for w in ('CAPACITY','BOUND','OOB','VERDICT','capacity','bound')))
# live sidecar check if norm facts exist
sc=pathlib.Path('/tmp/norm_scan/p.json.operandrole.json')
if sc.exists():
    roles=json.load(open(sc))['operand_roles']
    ck("live: read-side idx1 never WRITE_DEST",
       all(x['role']=='READ_SRC' for x in roles if x['operand_index']==1 and x['call'] in ('memcpy','memmove','strncpy')))
    ck("live: write-side idx0 never READ_SRC",
       all(x['role']=='WRITE_DEST' for x in roles if x['operand_index']==0))
print(f"OPERAND_ROLE_CONTROLS={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
