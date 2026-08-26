from pathlib import Path
import re, sys
text=Path('gate17_on.out').read_text().splitlines()
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
('Gate16 identity hard summary', ret.get('identity')==[0]),
('Gate16 constantize hard summary', ret.get('constantize')==[]),
('Gate16 MAY survives identity', may.get('wrapMayThroughIdentity')==('AMBIGUOUS',[1]) and ret.get('wrapMayThroughIdentity')==[]),
('Gate16 UNKNOWN survives identity', may.get('wrapUnknownThroughIdentity')==('UNKNOWN',[]) and ret.get('wrapUnknownThroughIdentity')==[]),
('Gate16 constant wrapper kills MAY', 'wrapMayThroughConstantize' not in may and ret.get('wrapMayThroughConstantize')==[]),
('Gate16 conditional MAY stays ambiguous', may.get('wrapMayConditional')==('AMBIGUOUS',[1]) and ret.get('wrapMayConditional')==[]),
('Gate16 exact conditional stays hard only', 'conditionalExactOnly' not in may and ret.get('conditionalExactOnly')==[1]),
('concat preserves one MAY operand', may.get('wrapMayConcat')==('AMBIGUOUS',[1]) and ret.get('wrapMayConcat')==[]),
('concat unions two MAY operands', may.get('wrapMayConcatTwo')==('AMBIGUOUS',[1,3]) and ret.get('wrapMayConcatTwo')==[]),
('concat preserves UNKNOWN', may.get('wrapUnknownConcat')==('UNKNOWN',[]) and ret.get('wrapUnknownConcat')==[]),
('template preserves MAY', may.get('wrapMayTemplate')==('AMBIGUOUS',[1]) and ret.get('wrapMayTemplate')==[]),
('template unions two MAY operands', may.get('wrapMayTemplateTwo')==('AMBIGUOUS',[1,3]) and ret.get('wrapMayTemplateTwo')==[]),
('plain binary exact params remain hard only', 'concatExactOnly' not in may and ret.get('concatExactOnly')==[0,1]),
('unrelated binary does not inherit MAY', 'binaryUnrelated' not in may and ret.get('binaryUnrelated')==[]),
]
ok=0
for name,p in checks:
    print(('PASS' if p else 'FAIL'), name); ok += bool(p)
print(f'GATE17={ok}/{len(checks)}')
if ok != len(checks): sys.exit(1)
