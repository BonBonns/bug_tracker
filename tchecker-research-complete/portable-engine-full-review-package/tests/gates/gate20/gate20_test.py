from pathlib import Path
import json,re,sys,csv
base=Path('.')
model=json.loads((base/'state_results.json').read_text())

def parse_engine(path):
    hard={}; may={}
    for line in (base/path).read_text().splitlines():
        m=re.match(r'RET\s+\d+\s+(\S+)\s+params=.*positions=\[(.*?)\]',line)
        if m: hard[m.group(1)]=[] if not m.group(2).strip() else [int(x.strip()) for x in m.group(2).split(',')]
        m=re.match(r'MAY\s+\d+\s+(\S+)\s+params=.*resolution=(\S+)\s+positions=\[(.*?)\]',line)
        if m: may[m.group(1)]=(m.group(2),[] if not m.group(3).strip() else [int(x.strip()) for x in m.group(3).split(',')])
    return hard,may
on,may=parse_engine('gate20_on.out'); off,_=parse_engine('gate20_off.out')
checks=[
 ('adapter emits AST_DIM', int((base/'ast_dim_count.txt').read_text().strip())>=18),
 ('object static exact', on.get('objectStaticExact')==[1] and 'objectStaticExact' not in may),
 ('object different key isolated', on.get('objectStaticDifferent')==[]),
 ('object constant overwrite kills source', on.get('objectStaticOverwrite')==[]),
 ('dynamic object write is MAY not hard', on.get('objectDynamicWrite')==[] and may.get('objectDynamicWrite')==('AMBIGUOUS',[2])),
 ('dynamic object read is MAY not hard', on.get('objectDynamicRead')==[] and may.get('objectDynamicRead')==('AMBIGUOUS',[2])),
 ('array static exact', on.get('arrayStaticExact')==[1]),
 ('array different index isolated', on.get('arrayStaticDifferent')==[]),
 ('dynamic array write is MAY not hard', on.get('arrayDynamicWrite')==[] and may.get('arrayDynamicWrite')==('AMBIGUOUS',[2])),
 ('dynamic array read is MAY not hard', on.get('arrayDynamicRead')==[] and may.get('arrayDynamicRead')==('AMBIGUOUS',[2])),
 ('dynamic key on distinct receiver does not cross-taint', on.get('differentReceiver')==[]),
 ('legacy baseline is coarser on static different key', off.get('objectStaticDifferent')==[0,1]),
 ('legacy baseline is coarser on constant overwrite', off.get('objectStaticOverwrite')==[0,1]),
 ('legacy baseline hardens dynamic read', off.get('objectDynamicRead')==[0,1,2]),
]
ok=0
for n,p in checks:
    print(('PASS' if p else 'FAIL'),n); ok+=bool(p)
print(f'GATE20={ok}/{len(checks)}')
if ok!=len(checks): sys.exit(1)
