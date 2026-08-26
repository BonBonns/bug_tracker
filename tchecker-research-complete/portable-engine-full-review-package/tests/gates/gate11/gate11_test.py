import re,sys
on=open('gate11_on2.out').read(); off=open('gate11_off.out').read()
def pos(text,name):
 m=re.search(r'^RET \d+ '+re.escape(name)+r'.*positions=\[([^]]*)\]',text,re.M)
 if not m:return None
 return [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
checks={
 'topState':([1],[0]),
 'topConstantOverwrite':([],[0]),
 'directState':([1],[0]),
 'directConstant':([],[0]),
 'sameObject':([0],[]),
 'differentField':([0],[0]),
 'twoObjects':([],[]),
}
n=0
for k,(a,b) in checks.items():
 got=(pos(on,k),pos(off,k)); exp=(a,b); ok=got==exp; n+=ok
 print(('PASS' if ok else 'FAIL'),k,'on/off=',got,'expected=',exp)
print(f'GATE11={n}/{len(checks)}')
sys.exit(0 if n==len(checks) else 1)
