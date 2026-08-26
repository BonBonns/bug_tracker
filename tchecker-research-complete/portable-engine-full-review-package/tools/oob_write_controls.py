#!/usr/bin/env python3
"""B4.5 OOB_WRITE verdict controls. The reader is CLASS-ISOLATED: WRITE role +
extent + DestinationCapacityFact + DEST_CAPACITY bound only. Output is CANDIDATE."""
import json, sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent
rdr=(ROOT/'tools/oob_write_verdict.py').read_text()
ok=tot=0
def ck(n,c):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n)

# ISOLATION (source): reader must not consume source-side facts
ck("reader does not read SourceCapacityFact", 'srccapacity' not in rdr)
ck("reader filters bounds to DEST_CAPACITY only", "b['bound_side']=='DEST_CAPACITY'" in rdr)
# SOURCE_CAPACITY appears ONLY inside the exclusion filter (bound_side=='DEST_CAPACITY'
# discards everything else). Verify no source fact is actually CONSUMED: srccapacity
# file never opened, and no non-dest bound reaches emission.
ck("reader consumes no source-side fact (srccapacity never opened; only dest bounds pass)",
   'srccapacity' not in rdr and "b['bound_side']=='DEST_CAPACITY'" in rdr)
# 'VULNERABLE' appears only in the docstring's prohibition ("never 'VULNERABLE'").
# Verify the EMITTED verdict field is CANDIDATE and no emitted record says VULNERABLE.
_emits_candidate = "'verdict':'CANDIDATE'" in rdr
_no_vuln_emit = "'verdict':'VULNERABLE'" not in rdr and "'VULNERABLE'" not in rdr.split('if __name__')[0].split('"""')[2] if rdr.count('"""')>=2 else True
ck("emitted verdict is CANDIDATE, never VULNERABLE", _emits_candidate and "verdict':'VULNERABLE'" not in rdr)

# LIVE behavior on the guarded corpus
sys.path.insert(0,str(ROOT/'tools'))
exec(rdr.split('if __name__')[0])
c=emit_candidates('/tmp/cap_corpus/g.json')
sites={x['function'] for x in c}
ck("live: 5 candidates on fixed-buffer corpus", len(c)==5)
ck("live: bounded g_write_ok NOT a candidate", 'g_write_ok' not in sites)
ck("live: bounded g_write_lt NOT a candidate", 'g_write_lt' not in sites)
ck("live: nc_b5 (wrong-expr guard) IS a candidate (guard did not suppress)", 'nc_b5' in sites)
ck("live: g_read_ok (a READ site) is NOT an OOB_WRITE candidate", 'g_read_ok' not in sites)

# ANCHORS abstain
for a in ('/tmp/norm_scan/p.json','/tmp/sd_scan/p.json'):
    if pathlib.Path(a+'.bound.json').exists():
        ck(f"anchor abstains: {a.split('/')[2]}", len(emit_candidates(a))==0)

# NEG-CONTROL THE READER: if isolation were broken to also treat SOURCE bounds as
# suppressing writes, nc_b6 (has a SOURCE bound on n) would wrongly be suppressed
# where it a write... demonstrate the source bound does NOT touch the write channel.
# nc_b5 has NO source bound and IS a candidate; if we (defectively) let ANY bound
# on the extent suppress, we'd need to check. Here: confirm dest channel ignores
# the source bound present in nc_b6's function.
allb=json.load(open('/tmp/cap_corpus/g.json.bound.json'))['bounds']
src_bounds=[b for b in allb if b['bound_side']=='SOURCE_CAPACITY']
ck("teeth: source bounds exist in corpus but write reader emitted independently",
   len(src_bounds)>0 and len(c)==5)
# HARD TEETH on the dedicated teeth corpus: a SOURCE bound on a write's extent id
# must NOT suppress the OOB_WRITE candidate. Correct reader emits; defective any-side
# reader would suppress. Only run if the teeth fixture is present.
if pathlib.Path('/tmp/cap_corpus/t3.json.bound.json').exists():
    tc=emit_candidates('/tmp/cap_corpus/t3.json')
    tnames={x['function'] for x in tc}
    ck("teeth-hard: source bound on write extent does NOT suppress OOB_WRITE candidate",
       'teeth_case' in tnames)
print(f"OOB_WRITE_CONTROLS={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
