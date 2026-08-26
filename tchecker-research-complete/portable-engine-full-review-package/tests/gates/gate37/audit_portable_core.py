#!/usr/bin/env python3
from pathlib import Path
import re, sys
root = Path(__file__).resolve().parents[3] / 'core'
source_roots = [
    root/'program_graph'/'src'/'main'/'java',
    root/'provenance-neutral'/'src'/'main'/'java',
    root/'effects'/'src'/'main'/'java',
    root/'evidence'/'src'/'main'/'java',
    root/'runtime'/'src'/'main'/'java',
]
files = [p for r in source_roots if r.exists() for p in r.rglob('*.java')]

def boxed_identity(type_name):
    hits=[]
    for p in files:
        t=p.read_text(errors='replace')
        names=set(re.findall(r'\b'+re.escape(type_name)+r'\s+([A-Za-z_$][\w$]*)', t))
        for n in names:
            pat=re.compile(r'\b'+re.escape(n)+r'\s*==(?!=)|(?<![=!<>])==\s*\b'+re.escape(n)+r'\b')
            for i,line in enumerate(t.splitlines(),1):
                if pat.search(line): hits.append((p,i,line.strip()))
    return hits

long_hits=boxed_identity('Long')
integer_hits=boxed_identity('Integer')
text='\n'.join(p.read_text(errors='replace') for p in files)
checks = {
    'NO_LINKED_LIST': 'LinkedList' not in text,
    'NO_BOXED_LONG_IDENTITY_COMPARE': not long_hits,
    'NO_BOXED_INTEGER_IDENTITY_COMPARE': not integer_hits,
    'NO_LEGACY_AST_DEPENDENCY': all(x not in text for x in ['tools.php.ast2cpg', 'ast.php', 'ASTNode']),
}
for k,v in checks.items(): print(('PASS ' if v else 'FAIL ')+k)
for kind,hits in [('Long',long_hits),('Integer',integer_hits)]:
    for p,i,line in hits: print(f'HIT boxed_{kind} {p}:{i}: {line}')
print('AUDITED_JAVA_FILES='+str(len(files)))
if not all(checks.values()): sys.exit(1)
