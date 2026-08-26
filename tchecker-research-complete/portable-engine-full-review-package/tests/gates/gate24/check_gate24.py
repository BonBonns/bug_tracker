#!/usr/bin/env python3
import json, pathlib, sys
p=pathlib.Path(sys.argv[1])
d=json.loads(p.read_text())
checks=[]
def ck(name, ok, detail=""):
    checks.append((name,bool(ok),detail))
funcs=[f for f in d.get('functions',[]) if not f.get('is_external')]
by_name={f['name']:f for f in funcs}
ck('helper method exists','helper' in by_name)
ck('main method exists','main' in by_name)
if 'helper' in by_name:
    ps=by_name['helper']['parameters']
    ck('helper has value param', any(x['name']=='value' and x['index']>=1 for x in ps), str(ps))
if 'main' in by_name:
    ps=by_name['main']['parameters']
    ck('main has input param', any(x['name']=='input' and x['index']>=1 for x in ps), str(ps))
main_id=by_name.get('main',{}).get('id')
helper_id=by_name.get('helper',{}).get('id')
cs=[c for c in d.get('calls',[]) if c.get('name')=='helper' and (main_id is None or c.get('enclosing_function_id')==main_id)]
ck('main contains helper call',len(cs)==1,str(cs))
if cs:
    c=cs[0]
    ck('helper call has one demonstrated target',len(c.get('candidate_target_ids',[]))==1,str(c.get('candidate_target_ids')))
    ck('helper call targets helper',helper_id in c.get('candidate_target_ids',[]),str(c.get('candidate_target_ids')))
    ck('helper call resolution EXACT',c.get('resolution')=='EXACT',c.get('resolution',''))
    ck('helper argument includes input',any(a.get('index',-99)>=1 and a.get('name')=='input' for a in c.get('arguments',[])),str(c.get('arguments')))
ck('no security layer in frontend facts', all(k not in d for k in ('sources','sinks','vulnerabilities','findings')))
for name,ok,detail in checks:
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" :: {detail}" if detail and not ok else ''))
passed=sum(x[1] for x in checks)
print(f"GATE24={passed}/{len(checks)}")
sys.exit(0 if passed==len(checks) else 1)
