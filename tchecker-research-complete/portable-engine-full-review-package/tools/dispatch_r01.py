#!/usr/bin/env python3
"""DISPATCH-R01 (CHARACTERIZE ONLY): why does a call stay unresolved when a
same-named definition EXISTS in the repo? Classify the point at which evidence
disappears. No promotion, and no name-based inference."""
import json, sys
from collections import Counter, defaultdict

def main(work, tag, report):
    d = json.load(open(f'{work}/js.json'))
    s = json.load(open(report))['sides'][0]
    fns = {f['id']: f for f in d['functions']}
    bodied = set(c['enclosing_function_id'] for c in d['calls']) | \
             set(r['function_id'] for r in d.get('returns', []))
    internal = defaultdict(list)
    for f in d['functions']:
        if not f.get('is_external') and f['id'] in bodied: internal[f['name']].append(f)
    locals_by_fn = defaultdict(dict)
    for l in d.get('locals', []): locals_by_fn[l['method_id']][l['name']] = l
    assigns = defaultdict(list)
    for a in d.get('assignments', []): assigns[a['target_local_id']].append(a)
    # the population: sole-cause EXTERNAL_OR_UNRESOLVED_CALL whose name IS in-repo
    want = set()
    for r in s['rows']:
        a = r.get('abstention', '')
        if a.count('+') or not a.startswith('EXTERNAL_OR_UNRESOLVED_CALL'): continue
        nm = a.split(':', 1)[1]
        if nm in internal: want.add((r['function'], nm))
    cat = Counter(); ex = defaultdict(list); rows = []
    for c in d['calls']:
        enc = fns.get(c['enclosing_function_id'])
        if not enc or (enc['name'], c.get('name')) not in want: continue
        name = c['name']; cands = internal[name]
        mfn = c.get('method_full_name') or ''
        recv = c.get('receiver_name') or ''
        code = c.get('code') or ''
        tids = [t for t in c.get('candidate_target_ids', []) if t in fns]
        # where does the evidence stop?
        if tids and any(not fns[t].get('is_external') for t in tids):
            k = 'ALREADY_LINKED (not actually unresolved)'
        elif tids and all(fns[t].get('is_external') for t in tids):
            k = 'FRONTEND_EXTERNAL_STUB (linked to a stub, real def exists)'
        elif '.' in code.split('(')[0]:
            k = 'DYNAMIC_PROPERTY_LOOKUP (obj.method())'
        elif name in locals_by_fn.get(enc['id'], {}):
            defs = assigns.get(locals_by_fn[enc['id']][name]['id'], [])
            k = 'FUNCTION_VALUE_UNKNOWN (local binding, no callable evidence)' if not any(
                x['value_ref']['kind'] == 'FUNCTION' for x in defs) else 'UNIQUE_TARGET_EVIDENCE_LOST'
        elif len(cands) > 1:
            k = 'MULTIPLE_VALID_TARGETS'
        elif len(cands) == 1:
            k = 'UNIQUE_TARGET_EVIDENCE_LOST (single in-repo def, no link)'
        else:
            k = 'OTHER'
        cat[k] += 1; ex[k].append(f"{enc['name']}::{code[:30]} mfn={mfn[:34]}")
        rows.append((c['id'], name, k))
    tot = sum(cat.values())
    print(f"=== {tag}: {tot} in-repo unresolved calls ===")
    for k, v in cat.most_common():
        print(f"  {v:4d}  {100*v//tot if tot else 0:3d}%  {k}")
        if ex[k]: print(f"          e.g. {ex[k][0]}")
    json.dump([r[0] for r in rows], open(f'/tmp/dispatch_ids_{tag}.json', 'w'))

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
