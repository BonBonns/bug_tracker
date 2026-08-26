#!/usr/bin/env python3
import base64, pathlib, sys
out=pathlib.Path(sys.argv[1]); out.mkdir(parents=True,exist_ok=True)
def b(s): return base64.b64encode(s.encode()).decode()
def row(*xs): return '\t'.join(str(x) for x in xs)
def w(name, lines): (out/name).write_text('\n'.join(lines)+('\n' if lines else ''))
w('meta.tsv',[row(b('CPP'),b('synthetic-memory-r02'),b('/src'))])
w('type_decls.tsv',[row(900,b('Box'),b('Box'),b('memory_r02.cpp'),1,'false','')])
w('members.tsv',[row(901,900,b('field'),b('int field'),b('int'),1)])
methods=[
 (100,'struct_field','struct_field:int(int)',1,5),
 (200,'pointer_field','pointer_field:int(int)',7,13),
 (300,'address_of_field','address_of_field:int(int)',15,21),
 (400,'array_exact','array_exact:int(int)',23,27),
 (500,'array_unknown_index','array_unknown_index:int(int,int)',29,34),
 (600,'set_value','set_value:void(int*,int)',36,38),
 (700,'pointer_param_caller','pointer_param_caller:int(int)',40,45),
 (800,'ambiguous_pointer_field','ambiguous_pointer_field:int(int)',47,55),
 (900,'nested_pointer_field_index','nested_pointer_field_index:int(int)',57,64),
]
w('methods.tsv',[row(i,b(n),b(fn),b('sig'),b('memory_r02.cpp'),lo,hi,b('NAMESPACE_BLOCK'),b('<global>'),'false') for i,n,fn,lo,hi in methods])
params=[
 (101,100,1,'input','int'),(201,200,1,'input','int'),(301,300,1,'input','int'),(401,400,1,'input','int'),
 (501,500,1,'input','int'),(502,500,2,'i','int'),(601,600,1,'p','int *'),(602,600,2,'v','int'),
 (701,700,1,'input','int'),(801,800,1,'input','int'),(901,900,1,'input','int')]
w('parameters.tsv',[row(i,mid,idx,b(n),b(n),b(t),1) for i,mid,idx,n,t in params])
w('method_returns.tsv',[row(mid+9000,mid,b('RET'),b('int' if mid!=600 else 'void'),hi) for mid,_,_,_,hi in methods])
locals_=[
 (110,100,'obj','Box'),
 (210,200,'obj','Box'),(211,200,'p','Box *'),
 (310,300,'obj','Box'),(311,300,'fp','int *'),
 (410,400,'buf','int[4]'),
 (510,500,'buf','int[4]'),
 (710,700,'x','int'),
 (810,800,'a','Box'),(811,800,'b','Box'),(812,800,'p','Box *'),
 (910,900,'obj','Box'),(911,900,'p','Box *'),
]
w('locals.tsv',[row(i,mid,b(n),b(n),b(t),1) for i,mid,n,t in locals_])
CALLS=[]; ARGS=[]; IDS=[]; LITS=[]
def ident(i,mid,name,typ,line,target): IDS.append(row(i,mid,b(name),b(name),b(typ),line,target)); return i
def lit(i,code,typ,line): LITS.append(row(i,b(code),b(typ),line)); return i
def op(i,mid,name,code,line,ops):
    CALLS.append(row(i,mid,b(name),b(name),b('STATIC_DISPATCH'),b('ANY'),b(code),b('memory_r02.cpp'),line,'',''))
    for idx,node,code0,name0,typ0,kind in ops: ARGS.append(row(node,i,idx,b(kind),b(code0),b(name0),b(typ0),line))
def invoke(i,mid,name,full,line,target,args):
    CALLS.append(row(i,mid,b(name),b(full),b('STATIC_DISPATCH'),b('ANY'),b(name+'(...)'),b('memory_r02.cpp'),line,str(target),b(full)))
    for idx,node,code0,name0,typ0,kind in args: ARGS.append(row(node,i,idx,b(kind),b(code0),b(name0),b(typ0),line))
def field(i,mid,base_node,base_code,field_name,line,indirect=False):
    fnode=i+50000
    op(i,mid,'<operator>.indirectFieldAccess' if indirect else '<operator>.fieldAccess',
       (base_code+'->' if indirect else base_code+'.')+field_name,line,
       [(1,base_node,base_code,base_code,'Box *' if indirect else 'Box','IDENTIFIER'),
        (2,fnode,field_name,field_name,'int','FIELD_IDENTIFIER')])
    return i
def index(i,mid,base_node,base_code,idx_node,idx_code,line,idx_kind='LITERAL'):
    op(i,mid,'<operator>.indexAccess',f'{base_code}[{idx_code}]',line,
       [(1,base_node,base_code,base_code,'int[4]','IDENTIFIER'),(2,idx_node,idx_code,idx_code,'int',idx_kind)])
    return i
# struct_field: obj.field=input; return obj.field
ident(1001,100,'obj','Box',2,110); field(1200,100,1001,'obj','field',2)
ident(1002,100,'input','int',2,101); op(1201,100,'<operator>.assignment','obj.field = input',2,[(1,1200,'obj.field','','int','CALL'),(2,1002,'input','input','int','IDENTIFIER')])
ident(1003,100,'obj','Box',3,110); field(1202,100,1003,'obj','field',3)
# pointer_field: p=&obj; p->field=input; return obj.field
ident(2001,200,'obj','Box',8,210); op(2200,200,'<operator>.addressOf','&obj',8,[(1,2001,'obj','obj','Box','IDENTIFIER')])
ident(2002,200,'p','Box *',8,211); op(2201,200,'<operator>.assignment','p=&obj',8,[(1,2002,'p','p','Box *','IDENTIFIER'),(2,2200,'&obj','','Box *','CALL')])
ident(2003,200,'p','Box *',9,211); field(2202,200,2003,'p','field',9,True)
ident(2004,200,'input','int',9,201); op(2203,200,'<operator>.assignment','p->field=input',9,[(1,2202,'p->field','','int','CALL'),(2,2004,'input','input','int','IDENTIFIER')])
ident(2005,200,'obj','Box',10,210); field(2204,200,2005,'obj','field',10)
# address_of_field: fp=&obj.field; *fp=input; return obj.field
ident(3001,300,'obj','Box',16,310); field(3200,300,3001,'obj','field',16)
op(3201,300,'<operator>.addressOf','&obj.field',16,[(1,3200,'obj.field','','int','CALL')])
ident(3002,300,'fp','int *',16,311); op(3202,300,'<operator>.assignment','fp=&obj.field',16,[(1,3002,'fp','fp','int *','IDENTIFIER'),(2,3201,'&obj.field','','int *','CALL')])
ident(3003,300,'fp','int *',17,311); op(3203,300,'<operator>.indirection','*fp',17,[(1,3003,'fp','fp','int *','IDENTIFIER')])
ident(3004,300,'input','int',17,301); op(3204,300,'<operator>.assignment','*fp=input',17,[(1,3203,'*fp','','int','CALL'),(2,3004,'input','input','int','IDENTIFIER')])
ident(3005,300,'obj','Box',18,310); field(3205,300,3005,'obj','field',18)
# array_exact: buf[0]=input; return buf[0]
ident(4001,400,'buf','int[4]',24,410); lit(4900,'0','int',24); index(4200,400,4001,'buf',4900,'0',24)
ident(4002,400,'input','int',24,401); op(4201,400,'<operator>.assignment','buf[0]=input',24,[(1,4200,'buf[0]','','int','CALL'),(2,4002,'input','input','int','IDENTIFIER')])
ident(4003,400,'buf','int[4]',25,410); lit(4901,'0','int',25); index(4202,400,4003,'buf',4901,'0',25)
# unknown index: buf[i]=input; return buf[0] -- must abstain
ident(5001,500,'buf','int[4]',30,510); ident(5002,500,'i','int',30,502); index(5200,500,5001,'buf',5002,'i',30,'IDENTIFIER')
ident(5003,500,'input','int',30,501); op(5201,500,'<operator>.assignment','buf[i]=input',30,[(1,5200,'buf[i]','','int','CALL'),(2,5003,'input','input','int','IDENTIFIER')])
ident(5004,500,'buf','int[4]',31,510); lit(5900,'0','int',31); index(5202,500,5004,'buf',5900,'0',31)
# set_value: *p=v
ident(6001,600,'p','int *',37,601); op(6200,600,'<operator>.indirection','*p',37,[(1,6001,'p','p','int *','IDENTIFIER')])
ident(6002,600,'v','int',37,602); op(6201,600,'<operator>.assignment','*p=v',37,[(1,6200,'*p','','int','CALL'),(2,6002,'v','v','int','IDENTIFIER')])
# caller: set_value(&x,input); return x
ident(7001,700,'x','int',41,710); op(7200,700,'<operator>.addressOf','&x',41,[(1,7001,'x','x','int','IDENTIFIER')])
ident(7002,700,'input','int',41,701); invoke(7201,700,'set_value','set_value:void(int*,int)',41,600,[(1,7200,'&x','','int *','CALL'),(2,7002,'input','input','int','IDENTIFIER')])
ident(7003,700,'x','int',42,710)
# ambiguous pointer field: p=&a; p=&b; p->field=input; return a.field -- no fabricated provenance
ident(8001,800,'a','Box',48,810); op(8200,800,'<operator>.addressOf','&a',48,[(1,8001,'a','a','Box','IDENTIFIER')])
ident(8002,800,'p','Box *',48,812); op(8201,800,'<operator>.assignment','p=&a',48,[(1,8002,'p','p','Box *','IDENTIFIER'),(2,8200,'&a','','Box *','CALL')])
ident(8003,800,'b','Box',49,811); op(8202,800,'<operator>.addressOf','&b',49,[(1,8003,'b','b','Box','IDENTIFIER')])
ident(8004,800,'p','Box *',49,812); op(8203,800,'<operator>.assignment','p=&b',49,[(1,8004,'p','p','Box *','IDENTIFIER'),(2,8202,'&b','','Box *','CALL')])
ident(8005,800,'p','Box *',50,812); field(8204,800,8005,'p','field',50,True)
ident(8006,800,'input','int',50,801); op(8205,800,'<operator>.assignment','p->field=input',50,[(1,8204,'p->field','','int','CALL'),(2,8006,'input','input','int','IDENTIFIER')])
ident(8007,800,'a','Box',51,810); field(8206,800,8007,'a','field',51)
# nested p->arr[0]=input; return obj.arr[0]
ident(9001,900,'obj','Box',58,910); op(9200,900,'<operator>.addressOf','&obj',58,[(1,9001,'obj','obj','Box','IDENTIFIER')])
ident(9002,900,'p','Box *',58,911); op(9201,900,'<operator>.assignment','p=&obj',58,[(1,9002,'p','p','Box *','IDENTIFIER'),(2,9200,'&obj','','Box *','CALL')])
ident(9003,900,'p','Box *',59,911); field(9202,900,9003,'p','arr',59,True); lit(9900,'0','int',59); index(9203,900,9202,'p->arr',9900,'0',59)
ident(9004,900,'input','int',59,901); op(9204,900,'<operator>.assignment','p->arr[0]=input',59,[(1,9203,'p->arr[0]','','int','CALL'),(2,9004,'input','input','int','IDENTIFIER')])
ident(9005,900,'obj','Box',60,910); field(9205,900,9005,'obj','arr',60); lit(9901,'0','int',60); index(9206,900,9205,'obj.arr',9901,'0',60)
w('calls.tsv',CALLS); w('arguments.tsv',ARGS); w('identifiers.tsv',IDS); w('literals.tsv',LITS)
w('returns.tsv',[
 row(1500,100,b('return obj.field'),3,'1202'), row(2500,200,b('return obj.field'),10,'2204'),
 row(3500,300,b('return obj.field'),18,'3205'), row(4500,400,b('return buf[0]'),25,'4202'),
 row(5500,500,b('return buf[0]'),31,'5202'), row(7500,700,b('return x'),42,'7003'),
 row(8500,800,b('return a.field'),51,'8206'), row(9500,900,b('return obj.arr[0]'),60,'9206')])
