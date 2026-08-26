from pathlib import Path
import json,sys
b=Path('.')
r=json.loads((b/'state_results.json').read_text())
checks=[
('object exact',r['objectDestructureExact']['paramPositions']==[1] and r['objectDestructureExact']['resolution']=='EXACT'),
('object rename',r['objectDestructureRename']['paramPositions']==[1] and r['objectDestructureRename']['resolution']=='EXACT'),
('different property isolated',r['objectDestructureDifferent']['paramPositions']==[]),
('overwrite kills source',r['objectDestructureOverwrite']['paramPositions']==[]),
('array exact',r['arrayDestructureExact']['paramPositions']==[1]),
('array index isolated',r['arrayDestructureDifferent']['paramPositions']==[]),
('computed destructure stays ambiguous',r['computedDestructure']['resolution']=='AMBIGUOUS' and 2 in r['computedDestructure']['paramPositions']),
('object rest stays ambiguous',r['objectRest']['resolution']=='AMBIGUOUS'),
('array rest stays ambiguous',r['arrayRest']['resolution']=='AMBIGUOUS'),
('distinct receiver isolated',r['distinctReceiver']['paramPositions']==[]),
('adapter lowers destructuring to AST_DIM',int((b/'ast_dim_count.txt').read_text())>=8),
]
ok=0
for n,p in checks: print(('PASS' if p else 'FAIL'),n); ok+=bool(p)
print(f'GATE21={ok}/{len(checks)}')
sys.exit(0 if ok==len(checks) else 1)
