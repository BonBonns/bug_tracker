import json,re,csv,sys
from pathlib import Path
base=str(Path(__file__).resolve().parent)
res=json.load(open(base+'/closure_results.json'))
checks=[]
def ck(name, cond, detail=''):
    checks.append((name,bool(cond),detail))
exp={
'closureDirect':[0], 'closureParam':[0], 'closureShadow':[], 'closureUnrelated':[],
'closureAlias':[0], 'closureMutation':[], 'closureMutationToSource':[0],
'nestedClosure':[0], 'closureTwoCaptures':[0,1], 'closureLocalShadowsOuter':[]}
for n,p in exp.items(): ck('model_'+n,res[n]['paramPositions']==p,f"got={res[n]['paramPositions']} expected={p}")
# adapter closure/capture structure
caps=json.load(open(base+'/csv/closure_captures.json'))
ck('adapter_has_closures', len(caps)==11, f'closures={len(caps)}')
capsets=[tuple(x['captures']) for x in caps]
ck('capture_sets', ('source',) in capsets and ('x',) in capsets and ('a','b') in capsets and () in capsets, str(capsets))
# real engine call bridge
err=open(base+'/csv/probe23.err').read(); out=open(base+'/csv/probe23.out').read(); off=open(base+'/csv/probe23_off.out').read()
ck('engine_complete_call_bridge', 'FRONTEND_RESOLUTION loaded=10 exact_edges_added=10 rejected=0' in err)
ck('closure_summary_loaded', 'FRONTEND_CLOSURE_RETURN loaded=10 rejected=0 complete=10' in err)
call_lines=[x for x in out.splitlines() if x.startswith('CALL ')]
ck('ten_exact_local_closure_calls', len(call_lines)==10, f'calls={len(call_lines)}')
# compare named function return summaries on/off
pat=re.compile(r'^RET \d+ (\w+) params=.* positions=\[(.*?)\]$',re.M)
def parse(txt):
 d={}
 for n,s in pat.findall(txt): d[n]=[] if not s.strip() else [int(x.strip()) for x in s.split(',')]
 return d
onm,offm=parse(out),parse(off)
ck('engine_gate_on_expected', all(onm.get(n)==p for n,p in exp.items()), str({n:onm.get(n) for n in exp}))
# At least the capture-dependent functions that should depend on source are missing without closure summary.
for n in ['closureDirect','closureAlias','closureMutationToSource','nestedClosure','closureTwoCaptures']:
    ck('off_misses_'+n, offm.get(n)!=exp[n], f'off={offm.get(n)} on={onm.get(n)}')
# Non-capture controls must remain clean on and off.
for n in ['closureShadow','closureUnrelated','closureMutation','closureLocalShadowsOuter']:
    ck('control_'+n, onm.get(n)==[] and offm.get(n)==[], f'off={offm.get(n)} on={onm.get(n)}')
passed=sum(x[1] for x in checks)
for n,ok,d in checks: print(('PASS' if ok else 'FAIL'),n,d)
print(f'GATE23={passed}/{len(checks)}')
sys.exit(0 if passed==len(checks) else 1)
