#!/usr/bin/env python3
"""Negative control for the KeySelector invariant relaxation: an empty-string
LITERAL key must be ACCEPTED, a MISSING one must still be REJECTED."""
import os, subprocess, sys, tempfile
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
BUILD=f'{ROOT}/tests/gates/jsts-r05/build'
d=tempfile.mkdtemp()
open(f'{d}/K.java','w').write('''
import portable.graph.*;
public class K {
  static void t(String n, Runnable r){
    try { r.run(); System.out.println(n+"=ACCEPTED"); }
    catch (IllegalArgumentException e){ System.out.println(n+"=REJECTED"); }
  }
  public static void main(String[] a){
    t("EMPTY",   () -> KeySelector.literal(""));        // legal JS obj[""]
    t("NULL",    () -> KeySelector.literal(null));      // genuinely missing
    t("NORMAL",  () -> KeySelector.literal("name"));
    t("DYN_OK",  () -> KeySelector.dynamic("ref"));
    t("DYN_NULL",() -> KeySelector.dynamic(null));      // must still be refused
  }
}''')
subprocess.run(['javac','-cp',BUILD,'-d',d,f'{d}/K.java'],capture_output=True)
out=subprocess.run(['java','-cp',f'{d}:{BUILD}','K'],capture_output=True,text=True).stdout
ok=tot=0
def ck(n,c,dd=''):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n+('' if c else f'  [{dd}]'))
ck('empty-string LITERAL key is ACCEPTED (legal JS obj[""])','EMPTY=ACCEPTED' in out,out)
ck('MISSING LITERAL key is still REJECTED','NULL=REJECTED' in out,out)
ck('ordinary literal key accepted','NORMAL=ACCEPTED' in out)
ck('dynamic ref accepted','DYN_OK=ACCEPTED' in out)
ck('missing dynamic ref still rejected','DYN_NULL=REJECTED' in out)
print(f'KEYSELECTOR_CONTROLS={ok}/{tot}')
sys.exit(0 if ok==tot else 1)
