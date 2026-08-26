#!/usr/bin/env python3
"""POLY-R01: merge a C/C++ program-facts doc and a JS/TS program-facts doc into one
graph, deriving cross-language call edges from the N-API binding table.

Everything here is frontend-side interpretation; the neutral Java loader and
engine are UNCHANGED. The linkage is mechanical, with refuse-on-ambiguity:
  C++ side: init's exports.Set(String::New(_, "<name>"), Function::New(_, <METHOD_REF>))
            -> binding name -> unique internal C++ method (0 or >1 matches = refuse)
  JS side:  calls whose method_full_name starts with 'node-gyp-build:' (jssrc2cpg's
            own import resolution) and whose name is in the table -> EXACT dispatch
            to the C++ function, reason NAPI_BINDING_TABLE.
Value projection across the N-API marshalling boundary is NOT claimed: the C++
callees take (CallbackInfo) and construct their returns, so callee summaries
abstain honestly; only DISPATCH is proven across the language boundary.
"""
import json, sys

OFFSET = 1 << 41   # keep the two Joern id spaces disjoint

def off(i):
    return i + OFFSET if isinstance(i, int) and i > 0 else i

def off_vr(vr):
    vr = dict(vr)
    if vr.get('kind') in ('PARAMETER', 'LOCAL', 'CALL') and isinstance(vr.get('id'), int) and vr['id'] > 0:
        vr['id'] = off(vr['id'])
    return vr

def offset_js(doc):
    d = json.loads(json.dumps(doc))  # deep copy
    for f in d['functions']:
        f['id'] = off(f['id'])
        for p in f['parameters']: p['id'] = off(p['id']); p['method_id'] = off(p.get('method_id', 0))
    for c in d['calls']:
        c['id'] = off(c['id']); c['enclosing_function_id'] = off(c['enclosing_function_id'])
        c['candidate_target_ids'] = [off(t) for t in c['candidate_target_ids']]
        for a in c.get('arguments', []):
            if 'value_ref' in a: a['value_ref'] = off_vr(a['value_ref'])
            if isinstance(a.get('id'), int): a['id'] = off(a['id'])
    for r in d.get('returns', []):
        r['id'] = off(r['id']); r['function_id'] = off(r['function_id'])
        r['value_ref'] = off_vr(r['value_ref'])
    for l in d.get('locals', []):
        l['id'] = off(l['id']); l['method_id'] = off(l['method_id'])
    for a in d.get('assignments', []):
        a['id'] = off(a['id']); a['function_id'] = off(a['function_id'])
        a['target_local_id'] = off(a['target_local_id'])
        a['value_ref'] = off_vr(a['value_ref'])
    for t in d.get('type_decls', []): t['id'] = off(t['id'])
    for m in d.get('members', []): m['id'] = off(m['id']); m['type_decl_id'] = off(m.get('type_decl_id', 0))
    for m in d.get('method_returns', []): m['id'] = off(m['id']); m['method_id'] = off(m['method_id'])
    for i in d.get('identifiers', []):
        i['id'] = off(i['id']); i['method_id'] = off(i['method_id'])
        i['ref_target_ids'] = [off(t) for t in i.get('ref_target_ids', [])]
    return d

def derive_binding_table(cpp):
    """exports.Set(String::New(_, LIT), Function::New(_, METHOD_REF)) -> {name: fid}"""
    calls_by_id = {c['id']: c for c in cpp['calls']}
    internal = {}
    for f in cpp['functions']:
        if not f['is_external'] and f['name'] not in ('<global>',):
            internal.setdefault(f['name'], []).append(f)
    table = {}; audit = []
    for c in cpp['calls']:
        if c['name'] != 'Set' or len(c.get('arguments', [])) < 2: continue
        a_name, a_fn = c['arguments'][0], c['arguments'][1]
        sub_name = calls_by_id.get(a_name['value_ref']['id']) if a_name['value_ref']['kind'] == 'CALL' else None
        sub_fn = calls_by_id.get(a_fn['value_ref']['id']) if a_fn['value_ref']['kind'] == 'CALL' else None
        if not sub_name or not sub_fn or sub_name['name'] != 'New' or sub_fn['name'] != 'New': continue
        lit = next((a for a in sub_name.get('arguments', []) if a['value_ref']['kind'] == 'CONSTANT'), None)
        mref = next((a for a in sub_fn.get('arguments', [])
                     if a['value_ref']['kind'] == 'UNKNOWN' and (a.get('code') or '').isidentifier()), None)
        if lit is None or mref is None: continue
        export_name = (lit['value_ref'].get('code') or lit.get('code') or '').strip().strip('"')
        method_name = mref['code'].strip()
        cands = internal.get(method_name, [])
        if len(cands) != 1:
            audit.append((export_name, method_name, f'REFUSED: {len(cands)} candidates'))
            continue
        table[export_name] = {'fid': cands[0]['id'],
                              'source_node_ids': [c['id'], sub_name['id'], sub_fn['id']]}
        audit.append((export_name, method_name, f'-> fid {cands[0]["id"]}'))
    return table, audit

def main():
    cpp = json.load(open(sys.argv[1]))
    js = json.load(open(sys.argv[2]))
    table, audit = derive_binding_table(cpp)
    print('N-API binding table (derived, refuse-on-ambiguity):')
    for name, mname, note in audit: print(f'  "{name}" = {mname} {note}')

    js = offset_js(js)
    linked = 0
    crosslang = []
    for c in js['calls']:
        mfn = c.get('method_full_name', '')
        # MEASURED native-module tags from jssrc2cpg's own import resolution:
        #   'node-gyp-build:<name>'   (bcrypt-style loader package)
        #   '<path>/native.node:<name>' (direct .node require)
        # Native-loader import tags emitted by jssrc2cpg. Measured: 'node-gyp-build:'
        # (node.bcrypt.js) and direct '<path>.node:'. Added 'bindings:' — the equally
        # common `require('bindings')('addon.node')` idiom, measured on node-addon-examples.
        is_native = (mfn.startswith('node-gyp-build:') or mfn.startswith('bindings:')
                     or '.node:' in mfn)
        if is_native and c['name'] in table:
            entry = table[c['name']]
            fid = entry['fid']
            full = next(f['full_name'] for f in cpp['functions'] if f['id'] == fid)
            # The merged doc's calls KEEP their frontend-native resolution: the
            # linkage lives ONLY in the portable-crosslang-facts sidecar, which the
            # Java core consumes as a first-class family (with derivation). The
            # merger no longer mutates dispatch.
            linked += 1
            crosslang.append({
                'js_call_id': c['id'], 'callee_function_id': fid,
                'export_name': c['name'], 'callee_full_name': full,
                'resolution': 'EXACT',
                'derivation': {'origin': 'FRONTEND_COMPOSED', 'rule': 'NAPI_BINDING_TABLE',
                               'source_node_ids': entry['source_node_ids'] + [c['id']]}})
    print(f'cross-language call edges linked: {linked}')

    # NAPI MARSHALLING (MEASURED anchor: constant-index info[k] reads lower to
    # <operator>.indirectIndexAccess; CPP-R02 synthesizes INDEX locations whose
    # base is the CallbackInfo PARAMETER). Bounded lowering: only for LINKED
    # callees with EXACTLY ONE declared parameter, and only constant slots.
    # The info param is replaced by synthetic positional params info[k] at index
    # k; every value_ref to the slot location is rewritten to that parameter.
    # Reads of `info` itself then dangle -> honest abstention (never guessed).
    # Variable-index slots produced no location (CPP-R02) -> abstain unchanged.
    fresh_pid = (1 << 42)
    linked_callees = {l['callee_function_id'] for l in crosslang}
    marshalled_by_callee = {}
    loc_by_id = {loc['id']: loc for loc in cpp.get('cpp_memory_locations', []) if 'id' in loc}
    for f in cpp['functions']:
        if f['id'] not in linked_callees: continue
        if len(f['parameters']) != 1: continue
        info_pid = f['parameters'][0]['id']
        slots = sorted(
            (loc for loc in loc_by_id.values()
             if loc['method_id'] == f['id'] and loc['kind'] == 'INDEX'
             and loc['base_id'] == info_pid and str(loc['selector']).isdigit()),
            key=lambda l: int(l['selector']))
        if not slots: continue
        rewrite = {}   # synthetic local id -> new parameter id
        new_params = []
        for loc in slots:
            k = int(loc['selector'])
            fresh_pid += 1
            new_params.append({'id': fresh_pid, 'method_id': f['id'], 'index': k,
                               'name': f"info[{k}]", 'code': f"info[{k}]",
                               'type_full_name': '<napi-marshalled-slot>', 'line': f.get('line', 0)})
            rewrite[loc['id']] = fresh_pid
        f['parameters'] = new_params
        marshalled_by_callee[f['id']] = {'positions': [p['index'] for p in new_params],
                                         'source_node_ids': [info_pid] + [l['id'] for l in slots]}
        def rw(vr):
            if vr.get('kind') == 'LOCAL' and vr.get('id') in rewrite:
                return {'kind': 'PARAMETER', 'id': rewrite[vr['id']], 'code': vr.get('code', '')}
            return vr
        for r in cpp.get('returns', []):
            if r['function_id'] == f['id']: r['value_ref'] = rw(r['value_ref'])
        for a2 in cpp.get('assignments', []):
            if a2['function_id'] == f['id']: a2['value_ref'] = rw(a2['value_ref'])
        for c2 in cpp['calls']:
            if c2['enclosing_function_id'] == f['id']:
                for arg in c2.get('arguments', []):
                    if 'value_ref' in arg: arg['value_ref'] = rw(arg['value_ref'])
    for l in crosslang:
        m = marshalled_by_callee.get(l['callee_function_id'])
        if m:
            l['marshalled_positions'] = m['positions']
            l['marshalling_derivation'] = {'origin': 'FRONTEND_COMPOSED', 'rule': 'NAPI_MARSHALLING',
                                           'source_node_ids': m['source_node_ids']}
    if marshalled_by_callee:
        print(f'marshalled callees: {len(marshalled_by_callee)} '
              f'(slots: {sorted(v["positions"] for v in marshalled_by_callee.values())})')

    merged = {
        'schema': cpp['schema'],
        'frontend': 'polyglot(joern-c2cpg+joern-jssrc2cpg)',
        'metadata': cpp.get('metadata', []) + js.get('metadata', []),
        'type_decls': cpp['type_decls'] + js['type_decls'],
        'members': cpp['members'] + js['members'],
        'functions': cpp['functions'] + js['functions'],
        'method_returns': cpp.get('method_returns', []) + js.get('method_returns', []),
        'locals': cpp.get('locals', []) + js.get('locals', []),
        'calls': cpp['calls'] + js['calls'],
        'identifiers': cpp.get('identifiers', []) + js.get('identifiers', []),
        'returns': cpp.get('returns', []) + js.get('returns', []),
        'assignments': cpp.get('assignments', []) + js.get('assignments', []),
        'frontend_counters': {'cpp': cpp.get('frontend_counters', {}), 'js': js.get('frontend_counters', {})},
        'cpp_memory': cpp.get('cpp_memory', {}),
        'crosslang_links': linked,
    }
    # neutral crosslang sidecar: every derived edge carries FactDerivation, ready
    # for a future first-class portable-crosslang-facts loader in the Java core.
    sidecar = {'schema': 'portable-crosslang-facts/0.1', 'links': crosslang}
    json.dump(sidecar, open(sys.argv[3] + '.crosslang.json', 'w'), indent=1, sort_keys=True)
    # id-collision hard check: the loader would also catch duplicates, but fail loudly here
    ids = [f['id'] for f in merged['functions']]
    assert len(ids) == len(set(ids)), 'function id collision after offset'
    json.dump(merged, open(sys.argv[3], 'w'), indent=1, sort_keys=True)
    print(f'merged: {len(merged["functions"])} functions, {len(merged["calls"])} calls -> {sys.argv[3]}')

if __name__ == '__main__':
    main()
