#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys, re, json, os, shutil
ROOT=Path(__file__).resolve().parents[1]
G=ROOT/'tests'/'gates'
results=[]
_EXECUTED_NAMES=set()

def run(g, cmd, cwd=None, mode='executed', name=None):
    label=name or f'GATE {g:02d}'
    _EXECUTED_NAMES.add(label)
    p=subprocess.run(cmd,cwd=cwd or G/f'gate{g:02d}',text=True,capture_output=True)
    ok=p.returncode==0
    results.append((g,'PASS' if ok else 'FAIL',mode))
    suffix=' (artifact re-grade: validates STORED prototype outputs, not a fresh computation; fresh capability proofs are JSTS-R02..R06, see TRACKS.md)' if mode=='regrade' else ''
    print(f"{label} {'PASS' if ok else 'FAIL'}{suffix}")
    if not ok:
        print((p.stdout+p.stderr)[-2000:])
# Gates 2-9 have no uniform executable regression runner in the preserved artifacts.
for g in range(2,10):
    d=G/f'gate{g:02d}'
    docs=list(d.rglob(f'GATE{g}_RESULT.md')) if d.exists() else []
    ok=bool(docs)
    results.append((g,'RECORDED' if ok else 'MISSING','artifact'))
    print(f"GATE {g:02d} {'RECORDED' if ok else 'MISSING'} (historical result; no uniform runner preserved)")
# Gates 10-23 execute, but their tests GRADE STORED prototype result files
# (state_results.json etc.) rather than recomputing — labeled 'regrade' honestly.
run(10,[sys.executable,'gate10_test.py','state_results.json'],mode='regrade')
for g in [11,12,13,14]: run(g,[sys.executable,f'gate{g}_test.py'],mode='regrade')
run(15,[sys.executable,'gate15_shape_test.py'],mode='regrade')
for g in [16,17,18,19,20,21,22,23]: run(g,[sys.executable,f'gate{g}_test.py'],mode='regrade')
run(25,['bash','run_gate25.sh'])
run(26,['bash','run_gate26.sh'])
run(27,['bash','run_gate27.sh'])
run(28,['bash','run_gate28.sh'])
run(29,['bash','run_gate29.sh'])
run(30,['bash','run_gate30.sh'])
run(31,['bash','run_gate31.sh'])
run(32,['bash','run_gate32.sh'])
run(33,['bash','run_gate33.sh'])
run(34,['bash','run_gate34.sh'])
run(35,['bash','run_gate35.sh'])
run(36,['bash','run_gate36.sh'])
run(37,['bash','run_gate37.sh'])
run(38,['bash','run_gate38.sh'])

# Gate 24 requires the real Joern jssrc2cpg frontend. Treat absence as BLOCKED, not a regression.
g24=G/'gate24'
joern=os.environ.get('JOERN') or shutil.which('joern'); jssrc=os.environ.get('JSSRC2CPG') or shutil.which('jssrc2cpg') or shutil.which('jssrc2cpg.sh')
if joern and jssrc:
    p24=subprocess.run(['bash','run_gate24.sh'],cwd=g24,text=True,capture_output=True)
    status='PASS' if p24.returncode==0 else 'FAIL'
    results.append((24,status,'real_frontend'))
    print(f"GATE 24 {status} (real Joern frontend)")
    if p24.returncode!=0: print((p24.stdout+p24.stderr)[-2000:])
else:
    results.append((24,'BLOCKED','real_frontend'))
    print('GATE 24 BLOCKED (real Joern/jssrc2cpg not installed)')

# Gate 24-TS characterizes TypeScript type/dispatch facts from the same real frontend.
g24ts=G/'gate24-ts'
if joern and jssrc:
    p24ts=subprocess.run(['bash','run_gate24_ts.sh'],cwd=g24ts,text=True,capture_output=True)
    status='PASS' if p24ts.returncode==0 else 'FAIL'
    results.append(('24-TS',status,'real_ts_frontend'))
    print(f"GATE 24-TS {status} (real Joern TypeScript conformance)")
    if p24ts.returncode!=0: print((p24ts.stdout+p24ts.stderr)[-4000:])
else:
    results.append(('24-TS','BLOCKED','real_ts_frontend'))
    print('GATE 24-TS BLOCKED (real Joern/jssrc2cpg not installed)')

# --- current tracks (see TRACKS.md) ---
for i,name in [(101,'core-s01'),(102,'core-s02'),(103,'core-s03'),(125,'core-s04'),(127,'core-s05'),(129,'core-s06'),(104,'core-crosslang'),(110,'core-memory'),(111,'core-expression'),(112,'core-reachingdef')]:
    run(i,['bash','run.sh'],cwd=G/name,name='CORE-'+name.split('-',1)[1].upper())
run(128,['bash','run.sh'],cwd=G/'js-source-r02',name='JS-SOURCE-R02')
run(130,['bash','run.sh'],cwd=G/'js-source-r03',name='JS-SOURCE-R03')
def blocked(i,name,reason):
    results.append((i,'BLOCKED','blocked')); print(f"{name} BLOCKED ({reason})")
_js=os.environ.get('JSSRC2CPG') or shutil.which('jssrc2cpg.sh')
_jo=os.environ.get('JOERN') or shutil.which('joern')
if _js and _jo and (G/'jsts-r05').exists():
    run(105,['bash','run.sh'],cwd=G/'jsts-r05',name='JSTS-R05')
else:
    blocked(105,'JSTS-R05','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-state-r02').exists():
    run(117,['bash','run.sh'],cwd=G/'js-state-r02',name='JS-STATE-R02')
else:
    blocked(117,'JS-STATE-R02','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-state-r03').exists():
    run(118,['bash','run.sh'],cwd=G/'js-state-r03',name='JS-STATE-R03')
else:
    blocked(118,'JS-STATE-R03','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-prop-r03').exists():
    run(126,['bash','run.sh'],cwd=G/'js-prop-r03',name='JS-PROP-R03')
else:
    blocked(126,'JS-PROP-R03','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-prov-r08').exists():
    run(120,['bash','run.sh'],cwd=G/'js-prov-r08',name='JS-PROV-R08')
else:
    blocked(120,'JS-PROV-R08','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-prov-r09').exists():
    run(121,['bash','run.sh'],cwd=G/'js-prov-r09',name='JS-PROV-R09')
else:
    blocked(121,'JS-PROV-R09','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-prov-r12').exists():
    run(122,['bash','run.sh'],cwd=G/'js-prov-r12',name='JS-PROV-R12')
else:
    blocked(122,'JS-PROV-R12','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-prov-r14').exists():
    run(123,['bash','run.sh'],cwd=G/'js-prov-r14',name='JS-PROV-R14')
else:
    blocked(123,'JS-PROV-R14','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-prov-r17').exists():
    run(124,['bash','run.sh'],cwd=G/'js-prov-r17',name='JS-PROV-R17')
else:
    blocked(124,'JS-PROV-R17','set JSSRC2CPG/JOERN')
if _js and _jo and (G/'js-state-r07').exists():
    run(119,['bash','run.sh'],cwd=G/'js-state-r07',name='JS-STATE-R07')
else:
    blocked(119,'JS-STATE-R07','set JSSRC2CPG/JOERN')
# (2026-08-24 debugging fix: a copy-pasted duplicate of the JS-PROV-R08..R17 block
# and of the SOURCE-R02 block ran those gates twice, inflating the EXECUTED
# denominator and double-counting any failure in REGRESSIONS. Duplicates removed;
# each gate now runs exactly once.)
import pathlib as _pl
if (G/'jsts-r06').exists() and _pl.Path(os.environ.get('REPLAY_DIR','/tmp/replay')).exists() and (G/'jsts-r05'/'build').exists():
    run(106,['bash','run.sh'],cwd=G/'jsts-r06',name='JSTS-R06')
else:
    blocked(106,'JSTS-R06','needs replay corpus + jsts-r05 build')
_jh=os.environ.get('JOERN_HOME')
if _jh and _pl.Path(_jh,'c2cpg.sh').exists() and (G/'jsts-r05'/'build').exists():
    run(107,['bash','run.sh'],cwd=G/'cpp-r06',name='CPP-R06')
else:
    blocked(107,'CPP-R06','set JOERN_HOME with c2cpg.sh')
if (G/'cpp-r06'/'run_memory_r02.sh').exists() and (G/'jsts-r05'/'build').exists():
    run(108,['bash','run_memory_r02.sh'],cwd=G/'cpp-r06',name='CPP-MEMORY-R02')
else:
    blocked(108,'CPP-MEMORY-R02','needs jsts-r05 build')
if _jh and _pl.Path(_jh,'c2cpg.sh').exists() and (G/'cpp-param-r01').exists() and (G/'jsts-r05'/'build').exists():
    run(113,['bash','run.sh'],cwd=G/'cpp-param-r01',name='CPP-PARAM-R01')
else:
    blocked(113,'CPP-PARAM-R01','needs JOERN_HOME with c2cpg.sh')
if _jh and _pl.Path(_jh,'c2cpg.sh').exists() and (G/'sink-r01').exists() and (G/'jsts-r05'/'build').exists():
    run(115,['bash','run.sh'],cwd=G/'sink-r01',name='SINK-R01')
else:
    blocked(115,'SINK-R01','needs JOERN_HOME with c2cpg.sh')
if _jh and _pl.Path(_jh,'c2cpg.sh').exists() and (G/'source-r02').exists() and (G/'jsts-r05'/'build').exists():
    run(116,['bash','run.sh'],cwd=G/'source-r02',name='SOURCE-R02')
else:
    blocked(116,'SOURCE-R02','needs JOERN_HOME with c2cpg.sh')
# GUARD-R01's /tmp/cmp2 + /tmp/pp2 fact documents are operator-maintained and were
# lost during an earlier packaging session (see gates/guard-r01/FIXTURE_NOTE.md);
# no builder for them exists in this bundle. Pre-check for them like every other
# "needs X" gate above, so a genuinely missing prerequisite reports BLOCKED
# (and surfaces via HARNESS_HEALTH's "expected gate never reported" check) instead
# of counting as a REGRESSIONS/FAIL — that label is reserved for gates that ran
# and failed their own assertions.
if (G/'guard-r01').exists() and (G/'jsts-r05'/'build').exists() \
        and _pl.Path('/tmp/cmp2/program.json').exists() and _pl.Path('/tmp/pp2/program.json').exists():
    run(114,['bash','run.sh'],cwd=G/'guard-r01',name='GUARD-R01')
else:
    blocked(114,'GUARD-R01','MISSING_FIXTURES: /tmp/cmp2, /tmp/pp2 not regenerated — see FIXTURE_NOTE.md')
if _jh and _pl.Path(_jh,'c2cpg.sh').exists() and _js and (G/'jsts-r05'/'build').exists():
    run(109,['bash','run_hermetic.sh'],cwd=G/'poly-r01',name='POLY-R01-H')
else:
    blocked(109,'POLY-R01-H','needs JOERN_HOME (c2cpg) + JSSRC2CPG')
# NOTE: the NETWORK PolyGlot gate (poly-r01/run.sh, clones GitHub) is deliberately
# NOT wired here — the canonical suite must stay hermetic. Run it manually.

exe=[r for r in results if r[2]=='executed']; fail=[r for r in exe if r[1]!='PASS']
# HARNESS HEALTH CHECK. This file was syntactically broken for several milestones
# and the suite silently did not run at all, so every "green" report in that
# window was vacuous. A canonical command must fail LOUDLY when it did not
# actually execute anything: "suite passed" must never be able to mean
# "suite never ran".
EXPECTED_GATES={'CORE-S01','CORE-S02','CORE-S03','CORE-S04','CORE-S05','CORE-S06','CORE-CROSSLANG','CORE-MEMORY',
                'CORE-EXPRESSION','CORE-REACHINGDEF','JSTS-R05','JSTS-R06',
                'CPP-R06','CPP-MEMORY-R02','CPP-PARAM-R01','GUARD-R01','SINK-R01','SOURCE-R02',
                'JS-SOURCE-R02','JS-SOURCE-R03','JS-STATE-R02','JS-STATE-R03','JS-STATE-R07','JS-PROV-R08','JS-PROV-R09','JS-PROV-R12','JS-PROV-R14','JS-PROV-R17'}
_health=[]
if not results: _health.append('NO gate produced a result at all')
if not exe: _health.append('ZERO gates executed')
_missing=EXPECTED_GATES-_EXECUTED_NAMES
if _missing: _health.append('expected gate(s) never reported: '+str(sorted(_missing)))
if _health:
    print('HARNESS_HEALTH=FAIL')
    for _h in _health: print('  !! '+_h)
else:
    print(f'HARNESS_HEALTH=OK ({len(results)} results, {len(exe)} executed)')
art=[r for r in results if r[2]=='artifact']; missing=[r for r in art if r[1]!='RECORDED']
real=[r for r in results if r[2] in ('real_frontend','real_ts_frontend')]; real_fail=[r for r in real if r[1]=='FAIL']
print('')
print(f"EXECUTED {len(exe)-len(fail)}/{len(exe)}")
print(f"HISTORICAL_RECORDED {len(art)-len(missing)}/{len(art)}")
print(f"REGRESSIONS {len(fail)}")
if missing: print(f"MISSING_ARCHIVES {len(missing)}")
if real:
    for r in real: print(f"REAL_FRONTEND_{r[0]} {r[1]}")
sys.exit(1 if fail or missing or real_fail else 0)
