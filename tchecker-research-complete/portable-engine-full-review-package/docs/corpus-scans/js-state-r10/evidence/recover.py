import re
src = open('run/src/ops.ts').read().split('\n')
def strip(s):
    s = re.sub(r'/\*.*?\*/',' ',s,flags=re.S)
    s = re.sub(r'//[^\n]*',' ',s)
    s = re.sub(r'"(?:[^"\\]|\\.)*"',' ',s)
    s = re.sub(r"'(?:[^'\\]|\\.)*'",' ',s)
    return s
exp={'value == "admin"':'==','value === "admin"':'===','value != "admin"':'!=','value !== "admin"':'!==',
     'a == b === c':'===','a == b':'==','"a == b" === value':'===','a /* == */ === b':'===',
     'a\\n      ===\\n      b':'===','d! === b':'==='}
ok=0; tot=0
for line in open('spans.txt'):
    _,cl,l1,c1,codeL,l2,c2,code = line.rstrip('\n').split('|')
    l1,c1,l2,c2 = int(l1),int(c1),int(l2),int(c2)
    # lines 1-based, columns 0-based
    sc = c1 + len(codeL)
    if l1==l2: gap = src[l1-1][sc:c2]
    else:
        parts=[src[l1-1][sc:]]+[src[i-1] for i in range(l1+1,l2)]+[src[l2-1][:c2]]
        gap='\n'.join(parts)
    m = re.findall(r'!==|===|!=|==', strip(gap))
    got = m[0] if len(m)==1 else ('AMBIG'+str(m) if m else 'NONE')
    e = exp.get(code,'?')
    good = got==e; ok+=good; tot+=1
    print(f"  {code!r:34s} gap={gap!r:24s} -> {got!r:8s} exp={e!r:6s} {'OK' if good else 'MISMATCH'}")
print(f"R10 ACCEPTANCE: {ok}/{tot}")
