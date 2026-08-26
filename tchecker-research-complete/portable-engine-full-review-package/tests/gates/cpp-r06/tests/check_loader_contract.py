#!/usr/bin/env python3
import json,sys
p=json.load(open(sys.argv[1]))
checks=[]
def ck(name,cond):
    checks.append(bool(cond)); print(('PASS' if cond else 'FAIL'),name)
ck('schema exactly Fable R05',p.get('schema')=='portable-program-facts/0.3')
ck('frontend identifies c2cpg',p.get('frontend')=='joern-c2cpg')
fs={f['name']:f for f in p['functions']}
ck('four functions',set(('helper','passthrough','constant_value','mainflow'))<=set(fs))
ck('helper param normalized 0-based',fs['helper']['parameters'][0]['index']==0)
ck('passthrough params normalized [0,1]',[x['index'] for x in fs['passthrough']['parameters']]==[0,1])
rets={r['function_id']:r for r in p['returns']}
ck('helper return PARAMETER',rets[fs['helper']['id']]['value_ref']['kind']=='PARAMETER')
ck('passthrough return parameter b',rets[fs['passthrough']['id']]['value_ref']['id']==fs['passthrough']['parameters'][1]['id'])
ck('constant return CONSTANT',rets[fs['constant_value']['id']]['value_ref']=={'kind':'CONSTANT','id':-1,'code':'7'})
main_call=next(c for c in p['calls'] if c['enclosing_function_id']==fs['mainflow']['id'] and c['name']=='helper')
ck('direct C call EXACT',main_call['resolution']=='EXACT' and main_call['candidate_target_ids']==[fs['helper']['id']])
ck('explicit call arg normalized to index 0',main_call['arguments'][0]['index']==0)
ck('call arg resolves to mainflow parameter',main_call['arguments'][0]['value_ref']['id']==fs['mainflow']['parameters'][0]['id'])
ck('mainflow return is CALL',rets[fs['mainflow']['id']]['value_ref']['kind']=='CALL' and rets[fs['mainflow']['id']]['value_ref']['id']==main_call['id'])
ck('derivation on args',main_call['arguments'][0]['derivation']['origin']=='FRONTEND_DIRECT')
ck('derivation on returns',all('derivation' in r for r in p['returns']))
voids=p.get('void_returns',[])
ck('bare return separated from value returns',
   all(not r.get('is_void') and r.get('value_ref',{}).get('kind')!='VOID' for r in p['returns']))
ck('bare return retained for control-flow consumers',
   any(r['function_id']==fs['no_value_result']['id'] and r.get('is_void') and
       r.get('value_ref',{}).get('kind')=='VOID' for r in voids))
ck('frontend counters nonempty',p['frontend_counters']['exported_functions']>0)
print(f'CPP_FABLE_CONTRACT={sum(checks)}/{len(checks)}')
sys.exit(0 if all(checks) else 1)
