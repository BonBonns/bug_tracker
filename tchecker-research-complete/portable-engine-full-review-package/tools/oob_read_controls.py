#!/usr/bin/env python3
"""B4.6 OOB_READ controls. Class-isolated read reader; output CANDIDATE.
NC-R4 guard-presence-alone can't clear; NC-R5 unknown src cap abstains;
NC-R6 correctly source-bounded exact extent no candidate; NC-R7 dest bound on a
read extent must NOT suppress (hard teeth, must flip)."""
import json, os, subprocess, sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent

# task #42 (GUARD-R01): see oob_write_controls.py's own identical preamble for the full account
# -- self-heals a missing /tmp/cap_corpus by rebuilding from the committed source via the real
# c2cpg/joern/normalize pipeline, falls back to a clear BLOCKED exit (never a bare crash) only
# if that pipeline itself is unavailable.
_CAP_CORPUS=pathlib.Path('/tmp/cap_corpus')
if not (_CAP_CORPUS/'g.json').exists():
    _BUILDER=ROOT/'tests/gates/guard-r01/fixtures/cap_corpus/build_cap_corpus.sh'
    _JH=os.environ.get('JOERN_HOME', str(ROOT.parent/'joern-install'/'joern-cli'))
    _JOERN_OK=pathlib.Path(_JH,'c2cpg.sh').exists()
    if _BUILDER.exists() and _JOERN_OK:
        print(f"[oob_read_controls] /tmp/cap_corpus missing -- rebuilding via {_BUILDER}",
              file=sys.stderr)
        subprocess.run(['bash',str(_BUILDER)], check=True, env={**os.environ,'JOERN_HOME':_JH})
    else:
        print(f"BLOCKED: /tmp/cap_corpus is missing and cannot be rebuilt "
              f"(builder_present={_BUILDER.exists()}, joern_available={_JOERN_OK}) -- "
              f"run {_BUILDER} manually with JOERN_HOME set to a real joern-cli install",
              file=sys.stderr)
        sys.exit(20)

rdr=(ROOT/'tools/oob_read_verdict.py').read_text()
sys.path.insert(0,str(ROOT/'tools'))
exec(rdr.split('if __name__')[0])
ok=tot=0
def ck(n,c):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n)

# ISOLATION
# 'destcapacity' appears only in the docstring prohibition. Verify no CODE opens it:
# the file-open for capacity is srccapacity only.
_code=rdr.split('"""')[2] if rdr.count('"""')>=2 else rdr
ck("reader does not OPEN destcapacity (code, not docstring)", "destcapacity" not in _code)
ck("reader filters bounds to SOURCE_CAPACITY only", "b['bound_side']=='SOURCE_CAPACITY'" in rdr)
ck("emitted verdict is CANDIDATE, never VULNERABLE",
   "'verdict':'CANDIDATE'" in rdr and "verdict':'VULNERABLE'" not in rdr)
ck("class is OOB_READ, separate channel", "'class':'OOB_READ'" in rdr)

# LIVE fixed-buffer corpus
c=emit_candidates('/tmp/cap_corpus/g.json'); names={x['function'] for x in c}
ck("live: 1 OOB_READ candidate (matches frozen B4.4)", len(c)==1)
ck("live: candidate is mix_fixed src read", 'mix_fixed' in names)
# NC-R6: g_read_ok is correctly source-bounded -> NOT a candidate
ck("NC-R6: g_read_ok (source-bounded exact extent) NOT a candidate", 'g_read_ok' not in names)
# NC-R4: nc_b6 has a source bound (n<=sizeof(local_src)) on its read extent -> guard
#   presence alone doesn't clear UNLESS it's the exact extent+side. nc_b6's bound IS
#   valid on its extent, so nc_b6 not a candidate; but a write-only guard wouldn't clear.
ck("NC-R4: g_write_ok (a WRITE site, DEST guard) is not an OOB_READ candidate", 'g_write_ok' not in names)
# a READ site with only a DEST guard on its extent must still be a candidate: teeth_read
tr=emit_candidates('/tmp/cap_corpus/t5.json'); trn={x['function'] for x in tr}
ck("NC-R4/R7: teeth_read (DEST bound on read extent) IS a candidate (guard didn't clear)",
   'teeth_read' in trn)

# NC-R5: source capacity unknown -> abstain. anchors norm/simdis have no src cap.
for a in ('/tmp/norm_scan/p.json','/tmp/sd_scan/p.json'):
    if pathlib.Path(a+'.bound.json').exists():
        ck(f"NC-R5 anchor abstains (src cap unknown): {a.split('/')[2]}", len(emit_candidates(a))==0)

# NC-R7 HARD TEETH: defective any-side reader suppresses teeth_read; correct emits.
allb=json.load(open('/tmp/cap_corpus/t5.json.bound.json'))['bounds']
ANYb={b['checked_value_id'] for b in allb}
d=json.load(open('/tmp/cap_corpus/t5.json'))
roles=json.load(open('/tmp/cap_corpus/t5.json.operandrole.json'))['operand_roles']
scap={f['storage_value_id']:f for f in json.load(open('/tmp/cap_corpus/t5.json.srccapacity.json'))['src_capacities']}
fns={f['id']:f['name'] for f in d['functions']}; calls={c['id']:c for c in d['calls']}
op={}
for r in roles: op.setdefault(r['id'],{})[r['role']]=r
def defective():
    out=[]
    for cid,o in op.items():
        if 'EXTENT' not in o or 'READ_SRC' not in o: continue
        cc=calls[cid]
        e=next((a for a in cc.get('arguments',[]) if a['index']==o['EXTENT']['operand_index']),None)
        evid=(e or {}).get('value_ref',{}).get('referenced_id') or (e or {}).get('value_ref',{}).get('id')
        s=next((a for a in cc.get('arguments',[]) if a['index']==o['READ_SRC']['operand_index']),None)
        svid=(s or {}).get('value_ref',{}).get('referenced_id') or (s or {}).get('value_ref',{}).get('id')
        if evid is None or svid not in scap: continue
        if evid in ANYb: continue
        out.append(fns.get(cc.get('enclosing_function_id')))
    return out
ck("NC-R7 teeth FLIP: defective any-side reader suppresses teeth_read", 'teeth_read' not in defective())
print(f"OOB_READ_CONTROLS={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
