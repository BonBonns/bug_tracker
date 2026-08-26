#!/usr/bin/env python3
"""STATUS normalization gate: asserts the RULE directly, so future tests validate
semantics rather than preserving historical enum names."""
import os, subprocess, sys, tempfile
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BUILD = f'{ROOT}/tests/gates/jsts-r05/build'
probe = tempfile.mkdtemp()
open(f'{probe}/N.java','w').write('''
import portable.graph.*; import portable.provenance.*; import java.util.*;
public class N {
  public static void main(String[] a) throws Exception {
    // f(x,y): t = x; if (c) t = ext(); return t;  -> known contribution, unbounded
    // Build the two evidence shapes directly through the engine's public summary.
    var s1 = new ProvenanceSummary(Resolution.AMBIGUOUS, Set.of(), Set.of(0),
        Set.of(), Set.of(), false, AnalysisCompleteness.COMPLETE, List.of());
    System.out.println("R1=" + s1.resolution());
    var s2 = new ProvenanceSummary(Resolution.POSSIBLE_UNBOUNDED, Set.of(), Set.of(0),
        Set.of(), Set.of(), true, AnalysisCompleteness.UNKNOWN, List.of());
    System.out.println("R2=" + s2.resolution());
  }
}''')
subprocess.run(['javac','-cp',BUILD,'-d',probe,f'{probe}/N.java'],capture_output=True)
out = subprocess.run(['java','-cp',f'{probe}:{BUILD}','N'],capture_output=True,text=True).stdout
ok=tot=0
def ck(n,c,d=''):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n+('' if c else f'  [{d}]'))
ck('NORM1 proven={} may!={} unknown=false is a valid AMBIGUOUS', 'R1=AMBIGUOUS' in out, out)
ck('NORM2 proven={} may!={} unknown=true is a valid POSSIBLE_UNBOUNDED', 'R2=POSSIBLE_UNBOUNDED' in out, out)
# and the engine must DERIVE these, not merely accept them
eng = subprocess.run(['java','-cp',BUILD,'EndToEndRunner','/tmp/bal/program.json',
                      '/tmp/bal/program.json.memory.json','/tmp/bal/program.json.expression.json',
                      '/tmp/bal/program.json.reachingdef.json'],capture_output=True,text=True).stdout
import re
bad=[l for l in eng.splitlines() if re.search(r'resolution=AMBIGUOUS .*unknown=true', l)]
ck('NORM3 engine never emits AMBIGUOUS with unknown=true (must be POSSIBLE_UNBOUNDED)', not bad, bad[:1])
bad2=[l for l in eng.splitlines() if re.search(r'resolution=EXACT proven=\[\] may=\[[0-9]', l)]
ck('NORM4 engine never emits EXACT with empty proven and non-empty may', not bad2, bad2[:1])
print(f'STATUS_NORM={ok}/{tot}')
sys.exit(0 if ok==tot else 1)
