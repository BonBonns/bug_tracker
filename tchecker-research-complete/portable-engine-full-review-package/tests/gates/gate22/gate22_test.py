from pathlib import Path
import json,sys
b=Path('.')
r=json.loads((b/'state_results.json').read_text())
checks=[
('object spread exact',r['objectSpreadExact']['paramPositions']==[1] and r['objectSpreadExact']['resolution']=='EXACT'),
('object override after kills source',r['objectSpreadOverrideAfter']['paramPositions']==[]),
('object spread after property restores source',r['objectSpreadOverrideBefore']['paramPositions']==[1]),
('later spread object wins constant',r['objectSpreadLaterObjectWins']['paramPositions']==[]),
('later spread object wins source',r['objectSpreadEarlierObjectLoses']['paramPositions']==[2]),
('dynamic write copied as ambiguous',r['objectSpreadDynamicWrite']['resolution']=='AMBIGUOUS' and 2 in r['objectSpreadDynamicWrite']['paramPositions']),
('array spread exact',r['arraySpreadExact']['paramPositions']==[1]),
('array spread prefix shifts index',r['arraySpreadPrefix']['paramPositions']==[1]),
('array spread suffix preserves index',r['arraySpreadSuffix']['paramPositions']==[1]),
('distinct receiver spread isolated',r['distinctReceiverSpread']['paramPositions']==[]),
]
ok=0
for n,p in checks: print(('PASS' if p else 'FAIL'),n); ok+=bool(p)
print(f'GATE22={ok}/{len(checks)}')
sys.exit(0 if ok==len(checks) else 1)
