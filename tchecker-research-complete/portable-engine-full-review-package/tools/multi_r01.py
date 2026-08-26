#!/usr/bin/env python3
"""MULTI-R01: split the residual MULTIPLE_SIGNATURE_MATCHES bucket into root
causes, with BOTH mention counts and sole-cause counts (the metric that predicts
what a single feature could actually move)."""
import json, sys, os
from collections import Counter, defaultdict

SYSTEM_PREFIXES = ('std.', '__gnu_cxx', '__', 'operator', '_')
def norm_type(t):
    t = (t or '').strip()
    for j in ('const ', 'volatile '): t = t.replace(j, '')
    return t.replace(' ', '').rstrip('&*') or 'ANY'
def head(full): return (full or '').split(':')[0]
def scope_of(full):
    h = head(full); p = h.split('.')
    return '.'.join(p[:-1]) if len(p) > 1 else ''

d = json.load(open(sys.argv[1]))
canon = {}
for c in json.load(open(sys.argv[2]))['canonical_definitions']:
    for i in c['instance_ids']: canon[i] = c['canonical_id']

fns = {f['id']: f for f in d['functions']}
bodied = set()
for c in d['calls']: bodied.add(c['enclosing_function_id'])
for l in d.get('locals', []): bodied.add(l['method_id'])
for r in d.get('returns', []): bodied.add(r['function_id'])
own = lambda f: not (f.get('full_name','') or '').startswith(SYSTEM_PREFIXES) and not f['name'].startswith('_')
defs = defaultdict(list)
for f in d['functions']:
    if f.get('is_external') or f['id'] not in bodied or not f.get('line') or not own(f): continue
    defs[f['name']].append(f)

mentions = Counter(); sole = Counter(); ex = defaultdict(list); total = 0
for c in d['calls']:
    n = c['name']
    if not n or n.startswith(('<','_')) or n in ('ANY','void'): continue
    e = fns.get(c['enclosing_function_id'])
    if not e or not own(e): continue
    if [t for t in c.get('candidate_target_ids', []) if t in fns and not fns[t].get('is_external')]: continue
    cands = defs.get(n, [])
    if not cands: continue
    args = c.get('arguments', [])
    by_arity = [f for f in cands if len(f.get('parameters', [])) == len(args)]
    if not by_arity: continue
    argt = [norm_type(a.get('type_full_name')) for a in args]
    if argt and all(t in ('ANY','','__type') for t in argt):
        typed = by_arity
    else:
        typed = [f for f in by_arity
                 if all(a == 'ANY' or norm_type(p.get('type_full_name')) == 'ANY' or a == norm_type(p.get('type_full_name'))
                        for a, p in zip(argt, f.get('parameters', [])))]
        if not typed: continue
    call_scope = scope_of(c.get('method_full_name', ''))
    if call_scope:
        sc = [f for f in typed if scope_of(f['full_name']) == call_scope]
        if sc: typed = sc
    # canonicalize
    seen = {}
    for f in typed: seen.setdefault(canon.get(f['id'], f['id']), f)
    typed = list(seen.values())
    if len(typed) < 2: continue
    total += 1
    causes = set()
    scopes = {scope_of(f['full_name']) for f in typed}
    sigs = {f['full_name'].split(':',1)[1] if ':' in f['full_name'] else '' for f in typed}
    if not call_scope: causes.add('RECEIVER_SCOPE_MISSING (call has no qualifying scope)')
    if any(not scope_of(f['full_name']) for f in typed):
        causes.add('CANONICALIZATION_MISS (unqualified/file-local candidates)')
    if len(scopes) == 1 and len(sigs) > 1: causes.add('TRUE_OVERLOAD_SET (same scope, differing signatures)')
    if len(scopes) > 1:
        roots = {s.split('.')[0] for s in scopes if s}
        causes.add('NAMESPACE_AMBIGUITY' if len(roots) > 1 else 'SAME_NAME_ACROSS_CLASSES')
    if any('<' in f['full_name'] or '<' in (f.get('signature') or '') for f in typed):
        causes.add('TEMPLATE_INSTANTIATION')
    if c.get('dispatch_type') == 'DYNAMIC_DISPATCH': causes.add('VIRTUAL/DYNAMIC_DISPATCH')
    if not causes: causes.add('OTHER')
    for k in causes: mentions[k] += 1
    if len(causes) == 1: sole[list(causes)[0]] += 1
    ex[sorted(causes)[0]].append(f"{n} x{len(typed)}")

print(f"MULTI-R01: {total} residual MULTIPLE calls\n")
print(f"{'cause':52s} {'mentions':>9s} {'sole':>6s} {'% residue':>10s}")
for k, v in mentions.most_common():
    print(f"  {k:50s} {v:9d} {sole.get(k,0):6d} {100*v/total:9.1f}%")
print("\nsamples:")
for k in list(mentions)[:4]:
    if ex[k]: print(f"  [{k[:34]}] {ex[k][0]}")
