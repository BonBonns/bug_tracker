from pathlib import Path
import re, sys
text=Path('gate19.out').read_text()

def block(name):
    m=re.search(rf'PATH_BEGIN {re.escape(name)}\n(.*?)\nPATH_END {re.escape(name)}', text, re.S)
    return m.group(1) if m else ''

checks=[]
b=block('wrapMay')
checks.append(('weakest edge caps exact call at AMBIGUOUS', 'path_resolution=AMBIGUOUS' in b and 'STEP CALL' in b and 'resolution=EXACT' in b and 'CALLEE_MAY_RETURN' in b and 'resolution=AMBIGUOUS' in b))
checks.append(('MAY cannot hard-project', 'hard_source_eligible=false' in b and 'HARD_PROJECTION=false' in b))
b=block('wrapMay2')
checks.append(('AMBIGUOUS survives two return hops', 'path_resolution=AMBIGUOUS' in b and 'CALLEE_MAY_RETURN' in b))
b=block('wrapMayLocal')
checks.append(('local assignment is shown as a path segment', 'STEP LOCAL_ASSIGN' in b and 'detail=[y]' in b and 'path_resolution=AMBIGUOUS' in b))
b=block('wrapMayThroughIdentity')
checks.append(('exact identity wrapper does not upgrade MAY', 'CALLEE_PROVEN_RETURN' in b and 'CALLEE_MAY_RETURN' in b and 'path_resolution=AMBIGUOUS' in b and 'HARD_PROJECTION=false' in b))
b=block('wrapMayConditional')
checks.append(('conditional join is path-AMBIGUOUS', 'STEP CONDITIONAL' in b and 'resolution=AMBIGUOUS' in b and 'HARD_PROJECTION=false' in b))
b=block('wrapMayConcat')
checks.append(('binary composition preserves uncertain path', 'STEP BINARY' in b and 'CALLEE_MAY_RETURN' in b and 'path_resolution=AMBIGUOUS' in b))
b=block('wrapUnknownConcat')
checks.append(('UNKNOWN path remains non-hard', 'status=UNKNOWN' in b and 'path_resolution=UNKNOWN' in b and 'HARD_PROJECTION=false' in b))
b=block('identity')
checks.append(('all-EXACT proven path may hard-project', 'status=PROVEN' in b and 'path_resolution=EXACT' in b and 'hard_source_eligible=true' in b and 'HARD_PROJECTION=true' in b))
b=block('concatExactOnly')
checks.append(('multi-parameter exact path remains hard eligible', 'positions=[0, 1]' in b and 'path_resolution=EXACT' in b and 'HARD_PROJECTION=true' in b))
checks.append(('reporter does not mutate hard summaries', 'PATH_REPORT_MUTATED_HARD=false' in text))
checks.append(('reporter does not mutate MAY or Vul Source state', 'PATH_REPORT_MUTATED_MAY=false' in text and 'PATH_REPORT_MUTATED_VUL_SOURCES=false' in text))

ok=0
for name,passed in checks:
    print(('PASS' if passed else 'FAIL'), name)
    ok += bool(passed)
print(f'GATE19={ok}/{len(checks)}')
if ok != len(checks): sys.exit(1)
