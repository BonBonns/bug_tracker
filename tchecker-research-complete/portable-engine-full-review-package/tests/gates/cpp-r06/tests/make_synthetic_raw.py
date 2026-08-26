#!/usr/bin/env python3
import base64, pathlib, sys
out=pathlib.Path(sys.argv[1]); out.mkdir(parents=True,exist_ok=True)
def b(s): return base64.b64encode(s.encode()).decode()
def w(name, lines): (out/name).write_text('\n'.join(lines)+('\n' if lines else ''))
# IDs deliberately arbitrary and unlike the JS fixtures.
w('meta.tsv',[f'{b("C")}'+'\t'+b('synthetic')+'\t'+b('/src')])
w('type_decls.tsv',[]); w('members.tsv',[])
methods=[(100,'helper','helper:int(int)','int(int)',1),(110,'passthrough','passthrough:int(int,int)','int(int,int)',2),(120,'constant_value','constant_value:int(int)','int(int)',3),(130,'mainflow','mainflow:int(int)','int(int)',4)]
w('methods.tsv',['\t'.join([str(i),b(n),b(fn),b(sig),b('app.c'),str(line),str(line),b('NAMESPACE_BLOCK'),b('<global>'),'false']) for i,n,fn,sig,line in methods])
params=[(101,100,1,'x','int x',1),(111,110,1,'a','int a',2),(112,110,2,'b','int b',2),(121,120,1,'x','int x',3),(131,130,1,'input','int input',4)]
w('parameters.tsv',['\t'.join([str(i),str(mid),str(idx),b(n),b(code),b('int'),str(line)]) for i,mid,idx,n,code,line in params])
w('method_returns.tsv',['\t'.join([str(mid+900),str(mid),b('RET'),b('int'),str(line)]) for mid,_,_,_,line in methods])
w('locals.tsv',[])
# helper(input) call: c2cpg/CPG explicit arg index starts at 1 for no-receiver call.
w('calls.tsv',['\t'.join(['200','130',b('helper'),b('helper:int(int)'),b('STATIC_DISPATCH'),b('int'),b('helper(input)'),b('app.c'),'4','100',b('helper:int(int)')])])
w('arguments.tsv',['\t'.join(['303','200','1',b('IDENTIFIER'),b('input'),b('input'),b('int'),'4'])])
# identifier nodes used as return expressions and call arg.
idents=[(301,100,'x','x',1,101),(302,110,'b','b',2,112),(303,130,'input','input',4,131)]
w('identifiers.tsv',['\t'.join([str(i),str(mid),b(n),b(code),b('int'),str(line),str(ref)]) for i,mid,n,code,line,ref in idents])
w('literals.tsv',['\t'.join(['401',b('7'),b('int'),'3'])])
# return nodes: helper->x, passthrough->b, constant->7, mainflow->call
w('returns.tsv',[ '\t'.join(['501','100',b('return x'),'1','301']), '\t'.join(['502','110',b('return b'),'2','302']), '\t'.join(['503','120',b('return 7'),'3','401']), '\t'.join(['504','130',b('return helper(input)'),'4','200']) ])
