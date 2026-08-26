import re,sys
from pathlib import Path
P=Path(__file__).parent
on=(P/'gate14_on.out').read_text(); hard=(P/'gate14_hard.out').read_text(); off=(P/'gate14_off.out').read_text(); err=(P/'gate14_on.err').read_text()
checks=[]
def add(n,ok,d): checks.append((n,bool(ok),d))
def ret(text,name):
    m=re.search(r'^RET \d+ '+re.escape(name)+r'.*positions=\[([^]]*)\]',text,re.M)
    return None if not m else [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
def may(text,name):
    m=re.search(r'^MAY \d+ '+re.escape(name)+r'.*resolution=([A-Z_]+) positions=\[([^]]*)\]',text,re.M)
    if not m:return None
    return m.group(1),[int(x.strip()) for x in m.group(2).split(',') if x.strip()]
add('seed_may_alias', may(on,'mayAliasWrite')==('AMBIGUOUS',[1]), may(on,'mayAliasWrite'))
add('seed_unknown', may(on,'mayAliasDifferentField')==('UNKNOWN',[]), may(on,'mayAliasDifferentField'))
add('one_hop_wrapper', may(on,'wrapMay')==('AMBIGUOUS',[1]), may(on,'wrapMay'))
add('two_hop_fixed_point', may(on,'wrapMay2')==('AMBIGUOUS',[1]), may(on,'wrapMay2'))
add('unknown_wrapper', may(on,'wrapUnknown')==('UNKNOWN',[]), may(on,'wrapUnknown'))
add('may_not_hardened_seed', ret(on,'mayAliasWrite')==[], ret(on,'mayAliasWrite'))
add('may_not_hardened_wrapper', ret(on,'wrapMay')==[] and ret(on,'wrapMay2')==[], (ret(on,'wrapMay'),ret(on,'wrapMay2')))
add('exact_channel_still_hard', ret(on,'wrapExact')==[1], ret(on,'wrapExact'))
add('uncertain_gate_off_silent', 'MAY ' not in hard and 'MAY ' not in off, ('MAY ' in hard,'MAY ' in off))
add('loader_counts', 'FRONTEND_STATE_MAY loaded=4 rejected=0 uncertain=4' in err and 'RETURN_MAY_SUMMARY functions=7 rounds=2' in err, err)
for n,ok,d in checks: print(('PASS' if ok else 'FAIL'),n,'-',d)
print(f'GATE14={sum(x[1] for x in checks)}/{len(checks)}')
sys.exit(0 if all(x[1] for x in checks) else 1)
