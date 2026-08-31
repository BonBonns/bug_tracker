#!/usr/bin/env python3
"""TOR-B2a OOB_COMPARE controls (task #33). Class-separation invariant: a capacity bound for
side A must NOT certify side B; safety requires n<=cap(A) AND n<=cap(B). Self-heals /tmp/cap_corpus
the same way oob_write_controls.py/oob_read_controls.py do (see their identical preamble)."""
import json, os, subprocess, sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent

_CAP_CORPUS=pathlib.Path('/tmp/cap_corpus')
if not (_CAP_CORPUS/'cmp.json').exists():
    _BUILDER=ROOT/'tests/gates/guard-r01/fixtures/cap_corpus/build_cap_corpus.sh'
    _JH=os.environ.get('JOERN_HOME', str(ROOT.parent/'joern-install'/'joern-cli'))
    _JOERN_OK=pathlib.Path(_JH,'c2cpg.sh').exists()
    if _BUILDER.exists() and _JOERN_OK:
        print(f"[oob_compare_controls] /tmp/cap_corpus/cmp.json missing -- rebuilding via {_BUILDER}",
              file=sys.stderr)
        subprocess.run(['bash',str(_BUILDER)], check=True, env={**os.environ,'JOERN_HOME':_JH})
    else:
        print(f"BLOCKED: /tmp/cap_corpus/cmp.json is missing and cannot be rebuilt "
              f"(builder_present={_BUILDER.exists()}, joern_available={_JOERN_OK}) -- "
              f"run {_BUILDER} manually with JOERN_HOME set to a real joern-cli install",
              file=sys.stderr)
        sys.exit(20)

rdr=(ROOT/'tools/oob_compare_verdict.py').read_text()
sys.path.insert(0,str(ROOT/'tools'))
exec(rdr.split('if __name__')[0])
ok=tot=0
def ck(n,c):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n)

# ISOLATION (structural)
ck("reader never reads WRITE_DEST or READ_SRC roles (compare-only)",
   "'WRITE_DEST'" not in rdr and "'READ_SRC'" not in rdr)
ck("emitted verdict is CANDIDATE, never VULNERABLE",
   "'verdict':'CANDIDATE'" in rdr and "verdict':'VULNERABLE'" not in rdr)
ck("class is OOB_COMPARE, separate channel", "'class':'OOB_COMPARE'" in rdr)
ck("safety requires BOTH sides (n<=A and n<=B), never either alone",
   "n<=A and n<=B" in rdr)

# LIVE: real, freshly-built cmp.json corpus
c=emit_candidates('/tmp/cap_corpus/cmp.json')
names={x['function'] for x in c}
ck("live: exactly 2 real OOB_COMPARE candidates", len(c)==2)
ck("live: cmp_safe (two-sided safe, literal extent==both capacities) NOT a candidate",
   'cmp_safe' not in names)
ck("live: cmp_overrun_b (extent exceeds side B only) IS a candidate, overruns=['B']",
   any(x['function']=='cmp_overrun_b' and x['overruns']==['B'] for x in c))
ck("live: cmp_overrun_sizeof (wrong-sizeof bug, extent exceeds side A only) IS a candidate, "
   "overruns=['A']",
   any(x['function']=='cmp_overrun_sizeof' and x['overruns']==['A'] for x in c))
ck("live: cmp_abstain_var (non-constant extent) NOT a candidate -- ABSTAIN, not a guess",
   'cmp_abstain_var' not in names)
ck("live: cmp_abstain_pointer (unresolved side-B capacity) NOT a candidate -- ABSTAIN",
   'cmp_abstain_pointer' not in names)

print(f"OOB_COMPARE_CONTROLS={ok}/{tot}")
sys.exit(0 if ok==tot else 1)
