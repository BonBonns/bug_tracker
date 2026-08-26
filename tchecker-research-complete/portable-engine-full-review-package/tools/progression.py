#!/usr/bin/env python3
"""Scaling progression: same filter, same matching rules, same buckets at every
checkpoint, so the trend is comparable across TU counts."""
import glob, json, subprocess, sys, tempfile, re, os
TOOLS = os.path.dirname(os.path.abspath(__file__))
tus = sorted(glob.glob('/tmp/tu/*/tu.json'))
checkpoints = [int(x) for x in sys.argv[1:]] or [4, 11, 20, 30, len(tus)]
BUCKETS = ['DEFINITION_ABSENT','INSUFFICIENT_TYPE_INFO','MULTIPLE_SIGNATURE_MATCHES',
           'SCOPE_CONFLICT(types)','SCOPE_CONFLICT(arity)',
           'UNIQUE_SIGNATURE_MATCH(same-TU)','UNIQUE_SIGNATURE_MATCH(cross-TU)']
rows = []
for n in checkpoints:
    if n > len(tus): continue
    m = tempfile.mktemp(suffix='.json')
    subprocess.run(['python3', f'{TOOLS}/merge_tus.py', m] + tus[:n], capture_output=True)
    out = subprocess.run(['python3', f'{TOOLS}/shadow_link.py', m], capture_output=True, text=True).stdout
    tot = int(re.search(r'over (\d+) unresolved', out).group(1))
    counts = {b: 0 for b in BUCKETS}
    for line in out.splitlines():
        mm = re.match(r'\s+(\d+)\s+(\d+)%\s+(\S.*)$', line)
        if mm and mm.group(3) in counts: counts[mm.group(3)] = int(mm.group(1))
    rows.append((n, tot, counts))
    os.unlink(m)
hdr = f"{'TUs':>4s} {'unres':>6s} " + " ".join(f"{b.replace('UNIQUE_SIGNATURE_MATCH','UNIQ').replace('SCOPE_CONFLICT','SCOPE')[:13]:>14s}" for b in BUCKETS)
print(hdr)
for n, tot, c in rows:
    print(f"{n:4d} {tot:6d} " + " ".join(f"{c[b]:5d}({100*c[b]//tot if tot else 0:2d}%)".rjust(14) for b in BUCKETS))
