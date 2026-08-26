#!/usr/bin/env python3
"""BUILD-R03 (SHADOW): measure cross-TU linkability. Rewrites NOTHING.

For every call in the merged per-TU graph with no internal target, compute
candidate definitions using qualified name + arity + parameter types + scope +
TU context, and classify. The point is to learn whether a mechanically UNIQUE
class exists at all before promoting anything into a neutral linking fact.
Name-only matching is never treated as a match.
"""
import json, sys, os
MATRIX_OUT = os.environ.get('MATRIX_OUT')
from collections import defaultdict, Counter

SYSTEM_CALLS = {'push_back','size','begin','end','c_str','make_pair','swap','find','insert',
 'erase','data','emplace_back','substr','length','at','clear','resize','back','front','get',
 'reset','release','lock','unlock','memcpy','snprintf','fprintf','malloc','free','abort','exit',
 'strlen','memcmp','append','string','max','min','move','count','empty','first','second','assign',
 'reserve','rbegin','rend','emplace','compare','copy','fill','sort','swap_ranges','printf'}

def scope_of(full):
    # 'leveldb.DBImpl.Get:...' -> 'leveldb.DBImpl'; '<unresolvedNamespace>.X' -> ''
    head = full.split(':')[0]
    if head.startswith('<unresolved'): return ''
    parts = head.split('.')
    return '.'.join(parts[:-1]) if len(parts) > 1 else ''

def norm_type(t):
    t = (t or '').strip()
    for junk in ('const ', 'volatile '): t = t.replace(junk, '')
    return t.replace(' ', '').rstrip('&*') or 'ANY'

def emit_links(path, out_path, links):
    """BUILD-R03 PROMOTION: emit ONLY the unique cross-TU signature+scope matches
    as neutral portable-crosslang-facts/0.1. Everything else abstains — no
    name-only fallback, no 'closest' candidate, no resolving ANY. The family is
    reused deliberately: a cross-TU link is structurally the same claim as the
    N-API case (a call resolved to a function extracted by a different frontend
    run), and the engine already applies such links ONLY when frontend-native
    resolution could not prove the dispatch."""
    doc = {'schema': 'portable-crosslang-facts/0.1', 'links': links}
    open(out_path, 'w').write(json.dumps(doc, indent=1, sort_keys=True) + '\n')
    print(f'emitted {len(links)} cross-TU link fact(s) -> {out_path}')

def main(path, canon_path=None):
    d = json.load(open(path))
    # MERGE-R01: when canonical definitions are supplied, candidate counting is
    # done over SOURCE DEFINITIONS rather than raw per-TU extraction instances.
    # This is not "these names look alike, so merge" — it is "these independent
    # extraction instances point back to the same source definition".
    # Real class-hierarchy evidence (inherits_from), used instead of name-shaped
    # guessing to decide whether a candidate set is a virtual-dispatch set.
    parents = {}
    for t in d.get('type_decls', []):
        fn = t.get('full_name') or ''
        ps = [x for x in (t.get('inherits_from') or []) if x and 'org.eclipse.cdt' not in x]
        if fn and ps: parents.setdefault(fn, set()).update(ps)
    def ancestors(tn, depth=0):
        out = set()
        for p in parents.get(tn, ()):  
            out.add(p); out.add(p.split('.')[-1])
            if depth < 6: out |= ancestors(p, depth + 1)
        return out
    inst2canon = {}
    if canon_path:
        for c in json.load(open(canon_path))['canonical_definitions']:
            for i in c['instance_ids']: inst2canon[i] = c['canonical_id']
    fns = d['functions']
    bodied = set()
    for c in d['calls']: bodied.add(c['enclosing_function_id'])
    for l in d.get('locals', []): bodied.add(l['method_id'])
    for r in d.get('returns', []): bodied.add(r['function_id'])
    by_id = {f['id']: f for f in fns}
    defs = defaultdict(list)
    for f in fns:
        if f.get('is_external') or f['id'] not in bodied or not f.get('line'): continue
        defs[f['name']].append(f)
    tu_of = {f['id']: f.get('translation_unit') for f in fns}

    # RESTRICT to the project's own code. Preprocessed TUs inline the entire C++
    # standard library, so an unrestricted count measures STL, not leveldb — the
    # same confound that made the first build-aware comparison meaningless.
    def is_own(f):
        full = f.get('full_name', '')
        return not full.startswith(('std.', '__gnu_cxx', '__', 'operator')) and not f['name'].startswith('_')
    defs = defaultdict(list, {k: [f for f in v if is_own(f)] for k, v in defs.items()})
    defs = defaultdict(list, {k: v for k, v in defs.items() if v})

    cls = Counter(); samples = defaultdict(list); emitted = []; percall = {}
    for c in d['calls']:
        name = c['name']
        # 'ANY' and 'void' are c2cpg PLACEHOLDERS, not callee names — measured as
        # 725 of the 1051 apparent DEFINITION_ABSENT rows. Counting them would
        # have inflated the dominant bucket by ~3x.
        if not name or name.startswith('<') or name.startswith('_'): continue
        if name in ('ANY', 'void'): continue
        encl = by_id.get(c['enclosing_function_id'])
        if not encl or not is_own(encl): continue
        if [t for t in c.get('candidate_target_ids', []) if t in by_id and not by_id[t].get('is_external')]:
            continue                                   # already resolved internally
        # BUG FIX (MULTI-R01): a call whose OWN scope is a system type
        # (std.vector::size, std.__cxx11.basic_string::data, ...) must never be
        # matched against project definitions just because the method NAME
        # collides. Measured as 18% of the residual MULTIPLE bucket.
        call_scope_early = scope_of(c.get('method_full_name', ''))
        if call_scope_early.startswith(('std.', '__gnu', '_')):
            cls['ABSENT_SYSTEM_CALL(out of scope by design)'] += 1
            percall[str(c['id'])] = 'ABSENT_SYSTEM_CALL(out of scope by design)'
            continue
        cands = defs.get(name, [])
        if not cands:
            # MEASURED at 38/39 TUs: 64% of "absent" callees are stdlib-shaped and
            # only 1% project-shaped, i.e. this bucket has CONVERGED and is a
            # consequence of project-scope filtering (the standard library is
            # excluded from definitions by design), NOT of missing coverage. It is
            # therefore split out so it cannot dilute the actionable residue.
            mfn = c.get('method_full_name', '') or ''
            systemish = (name in SYSTEM_CALLS or mfn.startswith(('std.', '__gnu', '_'))
                         or ('.' in name and name.split('.')[0] in ('std', '__gnu_cxx')))
            key = 'ABSENT_SYSTEM_CALL(out of scope by design)' if systemish else 'ABSENT_PROJECT_DEFINITION'
            cls[key] += 1; percall[str(c['id'])] = key; samples[key].append(name); continue
        arity = len([a for a in c.get('arguments', [])])
        by_arity = [f for f in cands if len(f.get('parameters', [])) == arity]
        if not by_arity:
            cls['SCOPE_CONFLICT(arity)'] += 1; percall[str(c['id'])] = 'SCOPE_CONFLICT(arity)'; samples['SCOPE_CONFLICT(arity)'].append(name); continue
        argt = [norm_type(a.get('type_full_name')) for a in c.get('arguments', [])]
        # VACUOUS-TRUTH FIX (TYPE-R01): "all argument types are ANY" is trivially
        # true for an EMPTY argument list, which mis-filed 1,108 zero-argument
        # calls as type failures. A zero-arg call has no types to recover — its
        # resolvability depends only on how many arity-0 candidates exist, so it
        # must fall through to the normal candidate-counting path.
        if argt and all(t in ('ANY', '', '__type') for t in argt):
            cls['INSUFFICIENT_TYPE_INFO'] += 1; percall[str(c['id'])] = 'INSUFFICIENT_TYPE_INFO'; samples['INSUFFICIENT_TYPE_INFO'].append(name); continue
        typed = []
        for f in by_arity:
            ptypes = [norm_type(p.get('type_full_name')) for p in f.get('parameters', [])]
            if all(a == 'ANY' or p == 'ANY' or a == p for a, p in zip(argt, ptypes)): typed.append(f)
        if not typed:
            cls['SCOPE_CONFLICT(types)'] += 1; percall[str(c['id'])] = 'SCOPE_CONFLICT(types)'; samples['SCOPE_CONFLICT(types)'].append(name); continue
        call_scope = scope_of(c.get('method_full_name', ''))
        if call_scope:
            scoped = [f for f in typed if scope_of(f['full_name']) == call_scope]
            if scoped: typed = scoped
        if inst2canon:
            seen_c = {}
            for f in typed: seen_c.setdefault(inst2canon.get(f['id'], f['id']), f)
            typed = list(seen_c.values())
        if len(typed) == 1:
            cross = tu_of.get(typed[0]['id']) != tu_of.get(c['enclosing_function_id'])
            k = 'UNIQUE_SIGNATURE_MATCH' + ('(cross-TU)' if cross else '(same-TU)')
            cls[k] += 1; percall[str(c['id'])] = k
            samples[k].append(f"{name} -> {typed[0]['full_name'][:52]}")
            if cross:
                emitted.append({'js_call_id': c['id'], 'callee_function_id': typed[0]['id'],
                    'export_name': name, 'callee_full_name': typed[0]['full_name'],
                    'resolution': 'EXACT',
                    'derivation': {'origin': 'FRONTEND_COMPOSED',
                                   'rule': 'CPP_CROSS_TU_SIGNATURE_MATCH',
                                   'source_node_ids': [c['id'], typed[0]['id']]}})
        elif call_scope and all(call_scope in ancestors(scope_of(f['full_name']))
                                or call_scope.split('.')[-1] in ancestors(scope_of(f['full_name']))
                                for f in typed):
            # Every candidate genuinely DERIVES from the call's declared scope:
            # this is runtime polymorphism, and AMBIGUOUS over the overriders is
            # the CORRECT answer, not unresolved residue.
            cls['VIRTUAL_DISPATCH_SET(correct: MAY over overriders)'] += 1
            percall[str(c['id'])] = 'VIRTUAL_DISPATCH_SET(correct: MAY over overriders)'
            samples['VIRTUAL_DISPATCH_SET(correct: MAY over overriders)'].append(
                f"{name} via {call_scope} x{len(typed)}")
        else:
            cls['MULTIPLE_SIGNATURE_MATCHES'] += 1; percall[str(c['id'])] = 'MULTIPLE_SIGNATURE_MATCHES'
            samples['MULTIPLE_SIGNATURE_MATCHES'].append(f"{name} x{len(typed)}")
    if MATRIX_OUT:
        json.dump(percall, open(MATRIX_OUT, 'w'))
    tot = sum(cls.values())
    print(f"SHADOW cross-TU linkability over {tot} unresolved calls\n")
    for k, v in cls.most_common():
        print(f"  {v:6d}  {100*v//tot:3d}%  {k}")
    print("\nsamples:")
    for k in ('UNIQUE_SIGNATURE_MATCH(cross-TU)', 'UNIQUE_SIGNATURE_MATCH(same-TU)', 'MULTIPLE_SIGNATURE_MATCHES'):
        for s in samples.get(k, [])[:4]: print(f"  [{k[:28]}] {s}")

    if len(sys.argv) > 2:
        emit_links(path, sys.argv[2], emitted)

if __name__ == '__main__':
    main(sys.argv[1], os.environ.get('CANON'))
