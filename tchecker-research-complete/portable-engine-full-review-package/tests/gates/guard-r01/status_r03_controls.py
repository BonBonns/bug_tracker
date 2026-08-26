#!/usr/bin/env python3
"""STATUS-R03 controls: impossible resolution/evidence combinations must be
REJECTED, and each control must be shown to fire on a known-bad input first.

NOTE the legitimate case that must NOT be rejected:
  EXACT + proven={} + may={} + unknown=false  ==  "analysis complete, no origins"
That is a positive no-flow answer and is valid.
"""
import subprocess, sys, tempfile, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BUILD = f'{ROOT}/tests/gates/jsts-r05/build'
probe = tempfile.mkdtemp()
open(f'{probe}/S.java','w').write('''
import portable.provenance.*; import portable.graph.*; import java.util.*;
public class S {
  static void t(String n, Runnable r){
    try { r.run(); System.out.println(n+"=ACCEPTED"); }
    catch (IllegalArgumentException e){ System.out.println(n+"=REJECTED"); }
  }
  public static void main(String[] a){
    // BAD: EXACT with nothing proven but a non-empty may set
    t("B1", () -> new ProvenanceSummary(Resolution.EXACT, Set.of(), Set.of(0),
        Set.of(), Set.of(), false, AnalysisCompleteness.COMPLETE, List.of()));
    // BAD: EXACT with unknown=true
    t("B2", () -> new ProvenanceSummary(Resolution.EXACT, Set.of(0), Set.of(),
        Set.of(), Set.of(), true, AnalysisCompleteness.UNKNOWN, List.of()));
    // BAD: POSSIBLE_UNBOUNDED with an empty may set
    t("B3", () -> new ProvenanceSummary(Resolution.POSSIBLE_UNBOUNDED, Set.of(), Set.of(),
        Set.of(), Set.of(), true, AnalysisCompleteness.UNKNOWN, List.of()));
    // GOOD: complete analysis, no origins (must be ACCEPTED)
    t("G1", () -> new ProvenanceSummary(Resolution.EXACT, Set.of(), Set.of(),
        Set.of(), Set.of(), false, AnalysisCompleteness.COMPLETE, List.of()));
    // GOOD: ordinary proven flow
    t("G2", () -> new ProvenanceSummary(Resolution.EXACT, Set.of(0), Set.of(),
        Set.of(), Set.of(), false, AnalysisCompleteness.COMPLETE, List.of()));
  }
}''')
subprocess.run(['javac','-cp',BUILD,'-d',probe,f'{probe}/S.java'],capture_output=True)
out = subprocess.run(['java','-cp',f'{probe}:{BUILD}','S'],capture_output=True,text=True).stdout
ok=tot=0
def ck(n,c,d=''):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n+('' if c else f'  [{d}]'))
ck('B1 EXACT with empty proven + non-empty may is REJECTED','B1=REJECTED' in out,out)
ck('B2 EXACT with unknown=true is REJECTED','B2=REJECTED' in out,out)
ck('B3 POSSIBLE_UNBOUNDED with empty may is REJECTED','B3=REJECTED' in out,out)
ck('G1 EXACT/no-origins/COMPLETE is ACCEPTED (positive no-flow answer)','G1=ACCEPTED' in out,out)
ck('G2 ordinary proven flow is ACCEPTED','G2=ACCEPTED' in out,out)
print(f'STATUS_R03_CONTROLS={ok}/{tot}')
sys.exit(0 if ok==tot else 1)
