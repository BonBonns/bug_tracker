import re, sys
ok=0; total=0
def ck(n, c):
    global ok,total; total+=1; ok+=bool(c); print(('PASS' if c else 'FAIL'), n)
for path, lang in zip(sys.argv[1:3], ('C','C++')):
    out=open(path).read()
    def s(name):
        m=re.search(r'SUMMARY '+name+r' resolution=(\S+) proven=\[([^\]]*)\]', out)
        return (m.group(1), [int(x) for x in m.group(2).split(',') if x.strip()]) if m else None
    ck(f'{lang}: loader accepted (frontend=joern-c2cpg)', 'frontend=joern-c2cpg' in out)
    ck(f'{lang}: helper EXACT[0]', s('helper')==('EXACT',[0]))
    ck(f'{lang}: passthrough EXACT[1]', s('passthrough')==('EXACT',[1]))
    ck(f'{lang}: constant no-origin', s('constant_value')==('EXACT',[]))
    ck(f'{lang}: mainflow EXACT[0] via C call graph', s('mainflow')==('EXACT',[0]))
print(f'CPP_R06={ok}/{total}')
sys.exit(0 if ok==total else 1)
