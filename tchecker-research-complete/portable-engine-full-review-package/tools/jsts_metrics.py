#!/usr/bin/env python3
"""JSTS-MEASURE-R01 refresh: five metric groups reported SEPARATELY."""
import json, subprocess, sys, re
from collections import defaultdict, Counter
def g(out, k):
    m = re.search(rf'(\d+)\s+\d+%\s+{re.escape(k)}', out); return int(m.group(1)) if m else 0
print(f"{'repo':14s}{'param→ret':>11s}{'returns':>9s}|{'EXACTdisp':>10s}{'ambig':>7s}|"
      f"{'EXACTcall':>10s}{'bounded':>8s}{'unkC':>6s}{'extC':>6s}|{'abstain':>8s}|{'auditPop':>9s}{'viol':>5s}")
for spec in sys.argv[1:]:
    tag, work, rep = spec.split(':')
    d = json.load(open(f'{work}/js.json')); s = json.load(open(rep))['sides'][0]
    rets = d.get('returns', [])
    pret = sum(1 for r in rets if r['value_ref']['kind'] == 'PARAMETER')
    fns = {f['id']: f for f in d['functions']}
    bodied = set(c['enclosing_function_id'] for c in d['calls']) | set(r['function_id'] for r in rets)
    exact = [c for c in d['calls'] if c.get('resolution') == 'EXACT' and len(c.get('candidate_target_ids', [])) == 1]
    ambig = sum(1 for c in d['calls'] if c.get('resolution') in ('AMBIGUOUS', 'HEURISTIC'))
    file_of = {f['id']: (f.get('file') or '') for f in d['functions']}
    byname = defaultdict(list)
    for f in d['functions']:
        if not f.get('is_external') and f['id'] in bodied: byname[f['name']].append(f)
    # audit POPULATION = promoted claims the audit can actually stress (cross-file EXACT)
    pop = sum(1 for c in exact if file_of.get(c['candidate_target_ids'][0]) != file_of.get(c['enclosing_function_id']))
    out = subprocess.run(['python3', 'hof_r02.py', work, tag], capture_output=True, text=True).stdout
    aud = subprocess.run(['python3', 'audit_claims.py', f'{work}/js.json', f'{work}/js_ts.engine.out'],
                         capture_output=True, text=True).stdout
    viol = sum(int(m.group(1)) for m in re.finditer(r'(\d+)\s+A[1-4]_\w+', aud))
    print(f"{tag:14s}{pret:11d}{len(rets):9d}|{len(exact):10d}{ambig:7d}|"
          f"{g(out,'EXACT_CALLABLE'):10d}{g(out,'BOUNDED_CALLABLE_SET'):8d}"
          f"{g(out,'UNKNOWN_CALLABLE'):6d}{g(out,'EXTERNAL_CALLABLE'):6d}|"
          f"{s['abstained']:8d}|{pop:9d}{viol:5d}")
