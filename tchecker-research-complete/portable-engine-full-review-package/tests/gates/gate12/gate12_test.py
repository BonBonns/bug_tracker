import re,sys
on=open('gate12_on.out').read(); off=open('gate12_off.out').read()
def pos(text,name):
    m=re.search(r'^RET \d+ '+re.escape(name)+r'.*positions=\[([^]]*)\]',text,re.M)
    if not m:return None
    return [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
checks={
 'aliasSame':([1],[0]),
 'aliasAllocation':([0],[]),
 'aliasOverwrite':([],[]),
 'aliasDistinct':([],[]),
 'aliasDifferentField':([],[]),
 'aliasDifferentParams':([0],[0]),
}
n=0
for k,exp in checks.items():
    got=(pos(on,k),pos(off,k)); ok=got==exp; n+=ok
    print(('PASS' if ok else 'FAIL'),k,'on/off=',got,'expected=',exp)
# Safety property: source is parameter 2 in aliasDifferentParams and must never be introduced.
safe=(2 not in (pos(on,'aliasDifferentParams') or []))
n+=safe
print(('PASS' if safe else 'FAIL'),'aliasDifferentParams_no_source_crossflow','on=',pos(on,'aliasDifferentParams'))
print(f'GATE12={n}/7')
sys.exit(0 if n==7 else 1)
