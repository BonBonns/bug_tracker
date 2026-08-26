import sys; sys.path.insert(0,'.')
from guard_fallthrough_verdict import derive as dg
from validation_bypass_verdict import derive as dv
from denylist_bypass_verdict import derive as dd
from malicious_npm_verdict import derive as dm
from globalmut_verdict import derive as dgl
from serialize_dos_verdict import derive as ds
raw, root, label = sys.argv[1], sys.argv[2], sys.argv[3]
R={'guard':dg(raw),'valid':dv(raw),'deny':dd(raw),'mal':dm(root,raw),'global':dgl(raw),'serial':ds(raw)}
line=f"{label:26s} |"
findings=[]
for k in ['guard','valid','deny','mal','global','serial']:
    fs=R[k]['findings']
    c=[f for f in fs if f.get('verdict','').startswith(('CANDIDATE','SUSPICIOUS'))]
    line+=f" {len(fs):>5d}"
    for f in c: findings.append((k,f))
line+=f" | CAND/SUSP={len(findings)}"
print(line)
for k,f in findings:
    loc=f.get('file') or f.get('method') or f.get('package') or '?'
    print(f"    [{k}] {f['verdict']}  {loc} L{f.get('line','')}")
# also report attacker-controlled serialize sinks specifically (the leg that matters)
import pathlib
p=pathlib.Path(raw)/'serialize_sinks.tsv'
if p.exists():
    rows=[l.split('\t') for l in p.read_text().splitlines() if l.strip()]
    atk=sum(1 for r in rows if len(r)>5 and r[5]=='true')
    if atk: print(f"    (serialize: {atk} ATTACKER-controlled sinks of {len(rows)})")
