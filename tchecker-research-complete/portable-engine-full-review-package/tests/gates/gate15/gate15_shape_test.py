import csv,sys
from collections import defaultdict
nodes={}
with open(str(__import__('pathlib').Path(__file__).parent/'csv'/'nodes.csv'),newline='') as f:
    r=csv.reader(f,delimiter='\t'); h=[x.split(':')[0] for x in next(r)]; I={k:i for i,k in enumerate(h)}
    for row in r:
        nodes[int(row[I['id']])]={'type':row[I['type']], 'funcid':int(row[I['funcid']] or 0), 'childnum':int(row[I['childnum']] or 0), 'name':row[I['name']].strip('"'), 'code':row[I['code']].strip('"')}
children=defaultdict(list)
with open(str(__import__('pathlib').Path(__file__).parent/'csv'/'rels.csv'),newline='') as f:
    r=csv.reader(f,delimiter='\t'); h=next(r)
    for row in r:
        a,b,t=int(row[0]),int(row[1]),row[2]
        if t=='PARENT_OF': children[a].append(b)
for p in children: children[p].sort(key=lambda n:nodes[n]['childnum'])
funcs={n['name']:i for i,n in nodes.items() if n['type']=='AST_FUNC_DECL'}
def varname(i):
    n=nodes[i]
    if n['type']!='AST_VAR': return None
    cs=children[i]
    return nodes[cs[0]]['code'] if cs else n['name']
def callname(i):
    if nodes[i]['type']!='AST_CALL': return None
    cs=children[i]
    if not cs:return None
    name=cs[0]
    if nodes[name]['type']!='AST_NAME':return None
    ns=children[name]
    return nodes[ns[0]]['code'] if ns else nodes[name]['name']
def assignments(fid):
    out=defaultdict(list)
    for i,n in nodes.items():
        if n['funcid']==fid and n['type']=='AST_ASSIGN':
            cs=children[i]
            if len(cs)>=2:
                v=varname(cs[0])
                if v: out[v].append(cs[1])
    return out
def resolve_expr(i,fid,depth=0):
    if depth>8:return None
    if nodes[i]['type']=='AST_CALL': return callname(i)
    v=varname(i)
    if not v:return None
    aa=assignments(fid).get(v,[])
    if len(aa)!=1:return None
    return resolve_expr(aa[0],fid,depth+1)
def returned_call(fn):
    fid=funcs[fn]
    rets=[i for i,n in nodes.items() if n['funcid']==fid and n['type']=='AST_RETURN']
    if len(rets)!=1:return None
    cs=children[rets[0]]
    return resolve_expr(cs[0],fid) if cs else None
expect={
 'wrapMayLocal':'mayAliasWrite',
 'wrapMayLocal2':'wrapMayLocal',
 'wrapUnknownLocal':'mayAliasDifferentField',
 'localUnrelated':None,
 'localOverwrite':None,
}
ok=0
for fn,e in expect.items():
    got=returned_call(fn); good=got==e; ok+=good
    print(('PASS' if good else 'FAIL'),fn,'->',got,'expected',e)
print(f'GATE15_SHAPE={ok}/{len(expect)}')
sys.exit(0 if ok==len(expect) else 1)
