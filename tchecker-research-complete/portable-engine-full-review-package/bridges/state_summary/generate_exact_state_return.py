#!/usr/bin/env python3
import csv,json,re,sys
nodes,tsfile,results,out=sys.argv[1:5]
fid={}
with open(nodes,newline='') as f:
    for row in csv.DictReader(f,delimiter='\t'):
        if row['type']=='AST_FUNC_DECL': fid[row['name']]=int(row['id:int'])
text=open(tsfile).read(); params={}
for m in re.finditer(r'function\s+(\w+)\s*\(([^)]*)\)',text):
    params[m.group(1)]=[p.strip().split(':',1)[0].strip() for p in m.group(2).split(',') if p.strip()]
res=json.load(open(results)); lines=['# fid\tCOMPLETE\tparam_positions']
for name,data in res.items():
    origins=data.get('origins',[])
    if not origins or any(o.startswith('STATE_UNKNOWN') or o=='UNKNOWN' for o in origins): continue
    pos=set(); ok=True
    for o in origins:
        if o.startswith('CONST:'): continue
        if o.startswith('PARAM:'):
            fn,pn=o[len('PARAM:'):].split('.',1)
            if fn!=name or pn not in params.get(name,[]): ok=False; break
            pos.add(params[name].index(pn))
        else: ok=False; break
    if ok and name in fid: lines.append(f"{fid[name]}\tCOMPLETE\t"+','.join(map(str,sorted(pos))))
open(out,'w').write('\n'.join(lines)+'\n')
