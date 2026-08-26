#!/usr/bin/env python3
"""MOD-R01 (CHARACTERIZE ONLY): module-origin values in JS/TS. Promotes nothing.

Splits every module-derived binding by the SHAPE of its origin, and asks which
shapes are mechanically resolvable INSIDE the analysed repo versus genuinely
external. Static local paths with a literal specifier are candidates; package
imports and dynamic requires are not.
"""
import json, re, sys, os
from collections import Counter, defaultdict

def classify(code, has_member):
    c = (code or '').strip()
    m = re.search(r'require\(\s*([\'"])(.+?)\1\s*\)', c)
    if m:
        spec = m.group(2)
        local = spec.startswith('.')
        if not local: return ('EXTERNAL_PACKAGE require("pkg")', spec)
        if has_member or re.search(r'require\([^)]*\)\s*\.\s*\w', c):
            return ('LOCAL require("./x").member', spec)
        return ('LOCAL require("./x") whole-module', spec)
    if re.search(r'require\(\s*[^\'"]', c): return ('DYNAMIC require(expr)', None)
    if c.startswith('import ') or ' from ' in c: return ('ESM import', None)
    return (None, None)

def main(work, label):
    d = json.load(open(f'{work}/js.json'))
    fns = {f['id']: f for f in d['functions']}
    locals_by_fn = defaultdict(dict)
    for l in d.get('locals', []): locals_by_fn[l['method_id']][l['name']] = l
    assigns = defaultdict(list)
    for a in d.get('assignments', []): assigns[a['target_local_id']].append(a)

    # 1) repo-wide inventory of module-origin bindings
    inv = Counter(); specs = Counter()
    for a in d.get('assignments', []):
        k, spec = classify(a['value_ref'].get('code'), False)
        if k: inv[k] += 1; specs[spec] += 1 if spec else 0
    # 2) the UNKNOWN callables: what module shape do they come from?
    cat = Counter(); ex = defaultdict(list); tot = 0
    for c in d['calls']:
        if c.get('resolution') == 'EXACT': continue
        name = c.get('name') or ''
        enc = fns.get(c['enclosing_function_id'])
        if not name or not enc or name.startswith('<operator>'): continue
        pn = {p['name'] for p in enc.get('parameters', [])}
        ln = locals_by_fn.get(enc['id'], {})
        if name in pn or name not in ln: continue
        tot += 1
        defs = assigns.get(ln[name]['id'], [])
        if not defs: cat['NO_DEFINITION_FACT']= cat['NO_DEFINITION_FACT']+1; continue
        v = defs[0]['value_ref']; code = v.get('code') or ''
        k, spec = classify(code, False)
        if k: cat[k] += 1; ex[k].append(f"{name} = {code[:34]}")
        elif v['kind'] == 'FUNCTION': cat['IN-REPO FUNCTION (already resolved by R08)'] += 1
        else: cat[f"NON-MODULE {v['kind']}"] += 1; ex[f"NON-MODULE {v['kind']}"].append(f"{name} = {code[:30]}")
    print(f"=== {label} ===")
    print(f"repo-wide module-origin bindings: {sum(inv.values())}")
    for k, v in inv.most_common(): print(f"   {v:5d}  {k}")
    print(f"unresolved local-callee sites: {tot}")
    for k, v in cat.most_common(7):
        print(f"   {v:5d}  {k}")
        if ex[k]: print(f"           e.g. {ex[k][0]}")

for spec in sys.argv[1:]:
    w, l = spec.split(':')
    main(w, l)
