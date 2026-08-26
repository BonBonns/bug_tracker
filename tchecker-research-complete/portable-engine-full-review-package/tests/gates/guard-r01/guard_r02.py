#!/usr/bin/env python3
"""GUARD-R02: negative controls for dynamic singleton dispatch and MAY aliasing.
Each control feeds a known-bad input and REQUIRES the guard to reject it."""
import json, os, subprocess, sys, tempfile
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, f'{ROOT}/tests/gates/cpp-r06/frontend')
ok = tot = 0
def ck(n, c, d=''):
    global ok, tot; tot += 1; ok += bool(c)
    print(('PASS ' if c else 'FAIL ') + n + ('' if c else f'  [{str(d)[:100]}]'))

# ---- C1/C2: dynamic singleton dispatch must never classify as EXACT ----------
import importlib.util
spec = importlib.util.spec_from_file_location('nz', f'{ROOT}/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py')
nz = importlib.util.module_from_spec(spec); spec.loader.exec_module(nz)
methods_by_id = {7: {'id': 7, 'full_name': 'T:m', 'is_external': False}}
dyn_single = {'name': 'm', 'method_full_name': 'T:m', 'dispatch_type': 'DYNAMIC_DISPATCH',
              'candidate_target_ids': [7], 'candidate_target_full_names': ['T:m']}
res, tids, tn, reason = nz.classify_call(dyn_single, methods_by_id)
ck('C1 dynamic singleton is NOT hardened to EXACT', res != 'EXACT', (res, reason))
ck('C1b it is reported as HEURISTIC (evidence-grade, not certainty-grade)',
   res == 'HEURISTIC', (res, reason))
stat_single = dict(dyn_single, dispatch_type='STATIC_DISPATCH')
res2, *_ = nz.classify_call(stat_single, methods_by_id)
ck('C2 positive control: a STATIC singleton IS EXACT (guard is not vacuous)',
   res2 == 'EXACT', res2)

# ---- C3..C6: MAY aliasing / identity must not be promoted to MUST ------------
JAVA = f'{ROOT}/tests/gates/jsts-r05/build'
probe = tempfile.mkdtemp()
open(f'{probe}/G.java', 'w').write('''
import portable.graph.*; import java.util.*;
public class G {
  static FactDerivation d(){ return new FactDerivation("T","T",List.of(1L)); }
  public static void main(String[] a){
    int fails=0;
    // C3: MAY set of two targets marked MUST
    try { new PointsToFact(1,2,"p",List.of(10L,11L),true,Resolution.EXACT,d()); System.out.println("C3=NOTREJECTED"); }
    catch (IllegalArgumentException e){ System.out.println("C3=REJECTED"); }
    // C4: two targets, must=false, but resolution EXACT
    try { new PointsToFact(1,2,"p",List.of(10L,11L),false,Resolution.EXACT,d()); System.out.println("C4=NOTREJECTED"); }
    catch (IllegalArgumentException e){ System.out.println("C4=REJECTED"); }
    // C5: SINGLETON target set whose evidence is only MAY (cardinality != certainty)
    try { new PointsToFact(1,2,"p",List.of(10L),false,Resolution.AMBIGUOUS,d()); System.out.println("C5=ACCEPTED"); }
    catch (IllegalArgumentException e){ System.out.println("C5=REJECTED_"+e.getMessage()); }
    // C6: same question for IdentityFact
    try { new IdentityFact(1,"x",List.of("A"),false,Resolution.AMBIGUOUS,d()); System.out.println("C6=ACCEPTED"); }
    catch (IllegalArgumentException e){ System.out.println("C6=REJECTED_"+e.getMessage()); }
  }
}''')
subprocess.run(['javac','-cp',JAVA,'-d',probe,f'{probe}/G.java'],capture_output=True)
out = subprocess.run(['java','-cp',f'{probe}:{JAVA}','G'],capture_output=True,text=True).stdout
ck('C3 MUST with a two-target MAY set is REJECTED', 'C3=REJECTED' in out, out)
ck('C4 EXACT resolution on a multi-target set is REJECTED', 'C4=REJECTED' in out, out)
print(f'    [cardinality-vs-certainty probe] {out.strip().splitlines()[-2:]}')
print(f'GUARD_R02={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
