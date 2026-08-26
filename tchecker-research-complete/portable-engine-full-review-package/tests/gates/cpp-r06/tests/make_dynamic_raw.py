#!/usr/bin/env python3
import base64,pathlib,sys
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
def b(s):return base64.b64encode(s.encode()).decode()
def w(n,ls):(out/n).write_text('\n'.join(ls)+('\n' if ls else ''))
w('meta.tsv',[b('C')+'\t'+b('synthetic')+'\t'+b('/src')]);w('type_decls.tsv',[]);w('members.tsv',[])
w('methods.tsv',['\t'.join(['10',b('target'),b('target:int(int)'),b('int(int)'),b('fp.c'),'1','1',b('NAMESPACE_BLOCK'),b('<global>'),'false']), '\t'.join(['20',b('caller'),b('caller:int(int)'),b('int(int)'),b('fp.c'),'2','2',b('NAMESPACE_BLOCK'),b('<global>'),'false'])])
w('parameters.tsv',['\t'.join(['11','10','1',b('x'),b('int x'),b('int'),'1']), '\t'.join(['21','20','1',b('x'),b('int x'),b('int'),'2'])])
w('method_returns.tsv',[]);w('locals.tsv',[])
w('calls.tsv',['\t'.join(['30','20',b('fp'),b('fp'),b('DYNAMIC_DISPATCH'),b('int'),b('fp(x)'),b('fp.c'),'2','10',b('target:int(int)')])])
w('arguments.tsv',['\t'.join(['31','30','1',b('IDENTIFIER'),b('x'),b('x'),b('int'),'2'])])
w('identifiers.tsv',['\t'.join(['31','20',b('x'),b('x'),b('int'),'2','21'])]);w('returns.tsv',[]);w('literals.tsv',[])
