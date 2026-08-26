#!/usr/bin/env python3
import json,re,sys
p=json.load(open(sys.argv[1])); text=open(sys.argv[2]).read(); ok=0; total=0
def ck(name,cond):
    global ok,total; total+=1; ok+=bool(cond); print(('PASS' if cond else 'FAIL'),name)
def summ(name):
    m=re.search(r'SUMMARY '+re.escape(name)+r' resolution=(\S+) proven=\[([^\]]*)\] may=\[([^\]]*)\] unknown=(\S+)',text)
    if not m:return None
    nums=lambda s:[int(x.strip()) for x in s.split(',') if x.strip()]
    return m.group(1),nums(m.group(2)),nums(m.group(3)),m.group(4)
st=p.get('cpp_memory',{}); A=p.get('assignments',[])
for name in ['struct_field','pointer_field','address_of_field','array_exact','pointer_param_caller','nested_pointer_field_index']:
    ck(name+' exact provenance',summ(name)==('EXACT',[0],[],'false'))
u=summ('array_unknown_index')
ck('unknown array index abstains',u is not None and u[1]==[] and u[2]==[] and u[3]=='true')
a=summ('ambiguous_pointer_field')
ck('ambiguous pointer field abstains',a is not None and a[1]==[] and a[2]==[] and a[3]=='true')
ck('field locations synthesized',st.get('exact_field_accesses',0)>=4)
ck('constant index location synthesized',st.get('exact_index_accesses',0)>=2)
ck('unknown index counted',st.get('unknown_index_accesses',0)>=1)
ck('pointer parameter write lowered at exact caller',st.get('exact_pointer_param_writes')==1)
ck('callee unresolved pointer param not hardened locally',st.get('unresolved_pointer_param_writes',0)>=0 and not any(a0['function_id']==600 and a0['derivation']['rule']=='CPP_EXACT_INDIRECT_WRITE' for a0 in A))
ck('all derived assignments have CPP rules',all(a0.get('derivation',{}).get('rule','').startswith('CPP_') for a0 in A))
import re as _re
_m=_re.search(r'MEMORY_FACTS locations=(\d+) points_to=(\d+)',text)
ck('memory fact family loaded as first-class (locations cross-validated by the core)',
   _m is not None and int(_m.group(1))==st.get('synthetic_locations',-1))

print(f'CPP_MEMORY_R02={ok}/{total}')
sys.exit(0 if ok==total else 1)
