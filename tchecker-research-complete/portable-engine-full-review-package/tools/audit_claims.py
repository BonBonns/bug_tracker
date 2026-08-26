#!/usr/bin/env python3
"""PROMOTION-VALIDITY AUDIT for JS/TS — audit the SUCCESS class, not just residue.

Carried over from the C++ arc, where 131 promoted cross-TU links turned out to be
false (system-scoped calls matched to project definitions by NAME). The analogous
hazard in JS/TS is jssrc2cpg's name-based call linking across a whole repo: two
unrelated modules defining the same function name can yield a confident but wrong
EXACT dispatch. Every claim the engine makes is checked structurally here.
"""
import json, re, sys
from collections import Counter, defaultdict

def main(doc_path, engine_out):
    d = json.load(open(doc_path))
    out = open(engine_out).read()
    fns = {f['id']: f for f in d['functions']}
    calls = {c['id']: c for c in d['calls']}
    bodied = set()
    for c in d['calls']: bodied.add(c['enclosing_function_id'])
    for r in d.get('returns', []): bodied.add(r['function_id'])
    by_name = defaultdict(list)
    for f in d['functions']:
        if not f.get('is_external'): by_name[f['name']].append(f)
    file_of = {f['id']: (f.get('file') or '') for f in d['functions']}

    checks = Counter(); flagged = defaultdict(list)
    # A1: every EXACT dispatch must have exactly one internal, bodied target
    for c in d['calls']:
        if c.get('resolution') != 'EXACT': continue
        tids = [t for t in c.get('candidate_target_ids', []) if t in fns]
        checks['exact_dispatch_total'] += 1
        if len(tids) != 1:
            checks['A1_exact_without_single_target'] += 1
            flagged['A1'].append(c.get('code','')[:40]); continue
        t = tids[0]
        if fns[t].get('is_external') or t not in bodied:
            checks['A2_exact_target_external_or_bodyless'] += 1
            flagged['A2'].append(f"{c['name']} -> {fns[t]['full_name'][:40]}"); continue
        # A3: cross-FILE link where the name is ambiguous repo-wide = the C++ bug shape
        same_named = [f for f in by_name.get(c['name'], []) if f['id'] in bodied]
        cross_file = file_of.get(t) != file_of.get(c['enclosing_function_id'])
        if cross_file and len(same_named) > 1:
            checks['A3_cross_file_link_with_ambiguous_name'] += 1
            flagged['A3'].append(f"{c['name']} x{len(same_named)} candidates, "
                                 f"{file_of.get(c['enclosing_function_id'],'?').split('/')[-1]} -> {file_of.get(t,'?').split('/')[-1]}")
        else:
            checks['A_ok_exact_dispatch'] += 1
    # A4: engine claims — every proven position must be a real parameter index
    for m in re.finditer(r'SUMMARY (\S+) resolution=(\S+) proven=\[([^\]]*)\]', out):
        name, res, pos = m.group(1), m.group(2), [int(x) for x in m.group(3).split(',') if x.strip()]
        if not pos: continue
        checks['claims_with_proven_positions'] += 1
        cands = by_name.get(name, [])
        if not cands: continue
        arity = max(len(f.get('parameters', [])) for f in cands)
        if any(p >= arity for p in pos):
            checks['A4_proven_position_out_of_range'] += 1
            flagged['A4'].append(f"{name} proven={pos} arity={arity}")
    print(f"CLAIM AUDIT for {doc_path.split('/')[-2] if '/' in doc_path else doc_path}")
    for k in ('exact_dispatch_total','A_ok_exact_dispatch','A1_exact_without_single_target',
              'A2_exact_target_external_or_bodyless','A3_cross_file_link_with_ambiguous_name',
              'claims_with_proven_positions','A4_proven_position_out_of_range'):
        print(f"  {checks.get(k,0):6d}  {k}")
    for k in ('A1','A2','A3','A4'):
        if flagged[k]: print(f"    [{k}] e.g. {flagged[k][0]}")

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
