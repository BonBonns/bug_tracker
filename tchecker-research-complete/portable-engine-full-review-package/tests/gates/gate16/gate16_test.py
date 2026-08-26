from pathlib import Path
import re, sys
text=Path('gate16_on.out').read_text().splitlines()
ret={}; may={}
for line in text:
    m=re.match(r'RET\s+(\d+)\s+(\S+)\s+params=.*positions=\[(.*?)\]', line)
    if m:
        vals=[] if not m.group(3).strip() else [int(x.strip()) for x in m.group(3).split(',')]
        ret[m.group(2)]=vals
    m=re.match(r'MAY\s+(\d+)\s+(\S+)\s+params=.*resolution=(\S+)\s+positions=\[(.*?)\]', line)
    if m:
        vals=[] if not m.group(4).strip() else [int(x.strip()) for x in m.group(4).split(',')]
        may[m.group(2)]=(m.group(3), vals)
checks=[
('Gate15 wrapMayLocal remains MAY', may.get('wrapMayLocal')==('AMBIGUOUS',[1])),
('Gate15 wrapMayLocal2 remains MAY', may.get('wrapMayLocal2')==('AMBIGUOUS',[1])),
('Gate15 wrapUnknownLocal remains UNKNOWN', may.get('wrapUnknownLocal')==('UNKNOWN',[])),
('Gate15 localUnrelated remains absent MAY', 'localUnrelated' not in may),
('Gate15 localOverwrite remains absent MAY', 'localOverwrite' not in may),
('identity hard summary is [0]', ret.get('identity')==[0]),
('constantize hard summary is []', ret.get('constantize')==[]),
('MAY survives exact identity', may.get('wrapMayThroughIdentity')==('AMBIGUOUS',[1]) and ret.get('wrapMayThroughIdentity')==[]),
('MAY survives identity after alias', may.get('wrapMayThroughIdentity2')==('AMBIGUOUS',[1]) and ret.get('wrapMayThroughIdentity2')==[]),
('UNKNOWN survives identity', may.get('wrapUnknownThroughIdentity')==('UNKNOWN',[]) and ret.get('wrapUnknownThroughIdentity')==[]),
('constant-return wrapper kills MAY', 'wrapMayThroughConstantize' not in may and ret.get('wrapMayThroughConstantize')==[]),
('conditional MAY union stays ambiguous', may.get('wrapMayConditional')==('AMBIGUOUS',[1]) and ret.get('wrapMayConditional')==[]),
('plain conditional exact param not laundered into MAY', 'conditionalExactOnly' not in may and ret.get('conditionalExactOnly')==[1]),
]
ok=0
for name,p in checks:
    print(('PASS' if p else 'FAIL'), name); ok += p
print(f'GATE16={ok}/{len(checks)}')
if ok != len(checks): sys.exit(1)
