#!/usr/bin/env python3
import json, pathlib, sys
p=pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
funcs=[f for f in d['functions'] if not f['is_external']]
by_name={f['name']:f for f in funcs}
types={t['name']:t for t in d['type_decls'] if not t['is_external']}

def calls_in(fn,name=None):
    fid=by_name.get(fn,{}).get('id')
    xs=[c for c in d['calls'] if c['enclosing_function_id']==fid]
    return [c for c in xs if name is None or c['name']==name]
def param(fn,name):
    for x in by_name.get(fn,{}).get('parameters',[]):
        if x['name']==name: return x
    return None

def one_call(fn,name='process'):
    xs=calls_in(fn,name)
    return xs[0] if len(xs)==1 else None

def show(c):
    if not c:return None
    return {k:c.get(k) for k in ('name','method_full_name','dispatch_type','resolution','candidate_target_full_names','code')}

checks=[]
def ck(name,ok,detail=''): checks.append((name,bool(ok),detail))
# Hard schema/type-preservation requirements. These should hold if TS type generation is active.
ck('type A exists','A' in types,str(list(types)))
ck('exact function exists','exact' in by_name)
pa=param('exact','obj')
ck('exact obj parameter exists',pa is not None,str(by_name.get('exact')))
ck('exact obj carries nonempty static type',bool(pa and pa.get('type_full_name')),str(pa))
pc=param('exact','x')
ck('string parameter carries nonempty type',bool(pc and pc.get('type_full_name')),str(pc))
ca=one_call('exact')
ck('exact process call represented',ca is not None,str(calls_in('exact')))
ck('exact process call has methodFullName',bool(ca and ca.get('method_full_name')),str(show(ca)))

# Property/return/interface/inheritance/generic/any are characterized rather than guessed.
observations={}
for fn in ['exact','unionCall','propertyCall','returnReceiver','interfaceCall','baseCall','childCall','genericCall','anyCall']:
    c=one_call(fn)
    observations[fn]={'parameter_types':{p['name']:p['type_full_name'] for p in by_name.get(fn,{}).get('parameters',[])},'call':show(c)}
# Verify fixture-level facts needed for later neutral mapping, but do not assume Joern's dispatch precision.
for fn in ['unionCall','propertyCall','returnReceiver','interfaceCall','baseCall','childCall','genericCall','anyCall']:
    ck(f'{fn} exists',fn in by_name)
    ck(f'{fn} process call represented',one_call(fn) is not None,str(calls_in(fn)))

# Typed property declaration and inheritance facts are standard CPG fields.
worker=[m for m in d['members'] if m['name']=='worker']
ck('Holder.worker member represented',len(worker)>=1,str(worker))
ck('Holder.worker has nonempty type',any(m.get('type_full_name') for m in worker),str(worker))
child=types.get('Child')
ck('Child type represented',child is not None,str(types.get('Child')))
ck('Child inheritance exposed',bool(child and child.get('inherits_from')),str(child))

print('--- Gate 24-TS checks ---')
for n,ok,detail in checks:
    print(('PASS ' if ok else 'FAIL ')+n+((' :: '+detail) if detail and not ok else ''))
print('\n--- Joern TS dispatch/type observations (no guessed expectations) ---')
print(json.dumps(observations,indent=2,sort_keys=True))
path=p.parent/'gate24_ts_observations.json'; path.write_text(json.dumps(observations,indent=2,sort_keys=True)+'\n')
passed=sum(ok for _,ok,_ in checks)
print(f'GATE24_TS={passed}/{len(checks)}')
sys.exit(0 if passed==len(checks) else 1)
