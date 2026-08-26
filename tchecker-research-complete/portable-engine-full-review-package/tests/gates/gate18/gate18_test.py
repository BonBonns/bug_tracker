from pathlib import Path
import re, sys
lines=Path('gate18.out').read_text().splitlines()
rec={}
for line in lines:
    m=re.match(r'EVID\s+(\S+)\s+ProvenanceEvidence: function=(\d+) status=(\S+) resolution=(\S+) positions=\[(.*?)\] hard_source=(\S+)', line)
    if not m: continue
    positions=[] if not m.group(5).strip() else [int(x.strip()) for x in m.group(5).split(',')]
    rec[m.group(1)]={'status':m.group(3),'resolution':m.group(4),'positions':positions,'hard':m.group(6)}
text='\n'.join(lines)
checks=[
 ('MAY exposed distinctly', rec.get('wrapMayConcat')=={'status':'MAY','resolution':'AMBIGUOUS','positions':[1],'hard':'false'}),
 ('multi-input MAY preserved', rec.get('wrapMayConcatTwo')=={'status':'MAY','resolution':'AMBIGUOUS','positions':[1,3],'hard':'false'}),
 ('UNKNOWN exposed distinctly', rec.get('wrapUnknownConcat')=={'status':'UNKNOWN','resolution':'UNKNOWN','positions':[],'hard':'false'}),
 ('exact evidence remains hard', rec.get('identity')=={'status':'PROVEN','resolution':'EXACT','positions':[0],'hard':'true'}),
 ('exact multi-input remains hard', rec.get('concatExactOnly')=={'status':'PROVEN','resolution':'EXACT','positions':[0,1],'hard':'true'}),
 ('unrelated value remains NONE', rec.get('binaryUnrelated')=={'status':'NONE','resolution':'NONE','positions':[],'hard':'false'}),
 ('MAY never labeled hard source', all(not(v['hard']=='true') for v in rec.values() if v['status']=='MAY')),
 ('UNKNOWN never labeled hard source', all(not(v['hard']=='true') for v in rec.values() if v['status']=='UNKNOWN')),
 ('reporter does not mutate hard propagation', 'REPORT_MUTATED_HARD=false' in lines),
 ('reporter does not mutate uncertain propagation', 'REPORT_MUTATED_MAY=false' in lines),
]
ok=0
for name,p in checks:
 print(('PASS' if p else 'FAIL'), name); ok+=bool(p)
print(f'GATE18={ok}/{len(checks)}')
if ok!=len(checks): sys.exit(1)
