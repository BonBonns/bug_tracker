#!/usr/bin/env python3
"""HOF-R02 (SHADOW): callee-position provenance. Promotes NOTHING.

The engine already follows values through capture chains; it does not apply that
same reasoning to answer "which function value is being invoked here?". This
follows the CALLEE expression through local identity -> capture chain -> outer
binding -> callable origin, and classifies the outcome.

A function value appears in the facts as value_ref{kind: UNKNOWN, code: '<lambda>N'}
(the frontend does not emit a method reference). The target is nonetheless
MECHANICALLY recoverable: the lambda's full_name is '<owner full_name>:<lambda>N'.
That is a scoped-name lookup, not name-guessing across the repo.
"""
import json, sys
from collections import Counter, defaultdict

def load(work):
    d = json.load(open(f'{work}/js.json'))
    try: caps = json.load(open(f'{work}/js_capture.json'))['captures']
    except Exception: caps = []
    return d, caps

def main(work, label):
    d, caps = load(work)
    fns = {f['id']: f for f in d['functions']}
    by_full = {f['full_name']: f for f in d['functions']}
    locals_by_fn = defaultdict(dict)
    for l in d.get('locals', []): locals_by_fn[l['method_id']][l['name']] = l
    assigns = defaultdict(list)
    for a in d.get('assignments', []): assigns[a['target_local_id']].append(a)
    cap_by_local = {c['inner_local_id']: c for c in caps}
    # argument values passed at each (function, param index) across all call sites
    passed = defaultdict(list)
    for c in d['calls']:
        for t in c.get('candidate_target_ids', []):
            for a in c.get('arguments', []):
                passed[(t, a['index'])].append(a)

    def lambda_target(owner_fn, code):
        if not code or not code.startswith('<lambda>'): return None
        return by_full.get(f"{owner_fn['full_name']}:{code}")

    def resolve_binding(fn, name, depth=0):
        """-> ('EXACT', fnfact) | ('BOUNDED', [..]) | ('UNKNOWN'|'EXTERNAL', None)"""
        if depth > 6: return ('UNKNOWN', None)
        f = fns.get(fn) if isinstance(fn, int) else fn
        if not f: return ('UNKNOWN', None)
        # parameter of this function -> what callers pass
        for p in f.get('parameters', []):
            if p['name'] == name:
                vals = passed.get((f['id'], p['index']), [])
                tgts = []
                for a in vals:
                    vr = a.get('value_ref') or {}
                    if vr.get('kind') == 'FUNCTION' and vr.get('id') in fns:
                        tgts.append(fns[vr['id']]); continue
                    t = lambda_target(f, (a.get('code') or ''))
                    if t: tgts.append(t)
                u = {t['id']: t for t in tgts}
                if len(u) == 1: return ('EXACT', list(u.values())[0])
                if len(u) > 1: return ('BOUNDED', list(u.values()))
                return ('UNKNOWN', None)
        loc = locals_by_fn.get(f['id'], {}).get(name)
        if not loc: return ('UNKNOWN', None)
        cap = cap_by_local.get(loc['id'])
        if cap:
            outer = fns.get(cap['outer_function'])
            if outer: return resolve_binding(outer, cap['outer_binding'], depth + 1)
        defs = assigns.get(loc['id'], [])
        if len(defs) == 1:
            v = defs[0]['value_ref']; code = v.get('code') or ''
            # JSTS-R08: a first-class FUNCTION value ref names its target directly.
            if v['kind'] == 'FUNCTION' and v.get('id') in fns:
                return ('EXACT', fns[v['id']])
            t = lambda_target(f, code)
            if t: return ('EXACT', t)
            if v['kind'] == 'CALL' and 'require(' in code: return ('EXTERNAL', None)
            return ('UNKNOWN', None)
        if len(defs) > 1:
            ts = [fns[x['value_ref']['id']] if x['value_ref']['kind'] == 'FUNCTION'
                  and x['value_ref'].get('id') in fns
                  else lambda_target(f, (x['value_ref'].get('code') or '')) for x in defs]
            # DEDUPE BY TARGET: two definitions naming the SAME function are one
            # callable, not a MAY set. Found by the JSTS-MEASURE-R01 controls —
            # without this, re-assignment of the same handler inflates
            # EXACT_CALLABLE into BOUNDED_CALLABLE_SET.
            uniq = {t['id']: t for t in ts if t}
            if len(uniq) > 1: return ('BOUNDED', list(uniq.values()))
            if len(uniq) == 1: return ('EXACT', list(uniq.values())[0])
        return ('UNKNOWN', None)

    cat = Counter(); ex = defaultdict(list); exact_links = []
    for c in d['calls']:
        if c.get('resolution') == 'EXACT': continue
        name = c.get('name') or ''
        if not name or name.startswith('<operator>'): continue
        enc = fns.get(c['enclosing_function_id'])
        if not enc: continue
        pn = {p['name'] for p in enc.get('parameters', [])}
        ln = set(locals_by_fn.get(enc['id'], {}))
        # `require` / `import` are module-loader BUILTINS modelled as external stubs
        # scoped under the program, not user callables. Counting them as
        # higher-order dispatch inflated eventemitter3's "unknown callable" bucket
        # to 76 when every one of them was literally a require(...) call.
        if name in ('require', 'import', '__require'): continue
        if name not in pn and name not in ln: continue
        kind, tgt = resolve_binding(enc, name)
        k = {'EXACT': 'EXACT_CALLABLE', 'BOUNDED': 'BOUNDED_CALLABLE_SET',
             'EXTERNAL': 'EXTERNAL_CALLABLE', 'UNKNOWN': 'UNKNOWN_CALLABLE'}[kind]
        cat[k] += 1
        if kind == 'EXACT':
            exact_links.append((c, tgt))
            ex[k].append(f"{enc['name']}::{name} -> {tgt['full_name'][-46:]}")
        elif kind == 'BOUNDED':
            ex[k].append(f"{enc['name']}::{name} x{len(tgt)}")
    tot = sum(cat.values())
    print(f"=== {label}: {tot} higher-order call sites, callee-position provenance ===")
    for k, v in cat.most_common():
        print(f"  {v:5d}  {100*v//tot if tot else 0:3d}%  {k}")
        if ex[k]: print(f"          e.g. {ex[k][0]}")
    # AUDIT: every shadow EXACT must be structurally sound
    bad = 0
    for c, t in exact_links:
        same_file = (t.get('file') or '') == (fns[c['enclosing_function_id']].get('file') or '')
        if t.get('is_external') or not same_file: bad += 1
    print(f"  AUDIT of shadow EXACT: {len(exact_links)} claims, {bad} cross-file/external (flagged)")

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
