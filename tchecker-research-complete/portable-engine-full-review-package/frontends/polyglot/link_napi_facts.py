#!/usr/bin/env python3
"""Cross-language composer: merges a JS/TS program-facts doc and a C/C++
program-facts doc into ONE portable-program-facts/0.3 document, resolving JS
`<receiver>.X(...)` native-binding calls to the C++ functions registered via the
N-API `exports.Set(Napi::String::New(env, "X"), Napi::Function::New(env, Fn))`
idiom (shape MEASURED on real c2cpg output of node.bcrypt.js).

Discipline: this is a FRONTEND. All cross-language interpretation happens here;
the neutral Java loader and provenance engine consume the merged document
unchanged. Only mechanically exact registrations are linked: a string literal
name + a METHOD_REF resolving to exactly ONE non-external function. Anything
else is left exactly as the JS frontend classified it (never hardened).

The two frontends emit overlapping Joern id spaces, so every id on the C/C++
side is offset by a disjoint constant before merging.
"""
import json, sys, argparse

OFFSET = 1 << 44  # far above any observed Joern id (~2^35); keeps both spaces disjoint

ID_KEYS = {'id','method_id','function_id','enclosing_function_id','target_local_id',
           'type_decl_id','receiver_node_id','base_id','index_call_id','assignment_call_id'}
ID_LIST_KEYS = {'candidate_target_ids','ref_target_ids','source_node_ids'}

def offset_ids(x):
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            if k in ID_KEYS and isinstance(v, int) and v > 0:
                out[k] = v + OFFSET
            elif k in ID_LIST_KEYS and isinstance(v, list):
                out[k] = [e + OFFSET if isinstance(e, int) and e > 0 else e for e in v]
            elif k == 'value_ref' and isinstance(v, dict):
                w = dict(v)
                if isinstance(w.get('id'), int) and w['id'] > 0:
                    w['id'] += OFFSET
                out[k] = w
            else:
                out[k] = offset_ids(v)
        return out
    if isinstance(x, list):
        return [offset_ids(e) for e in x]
    return x

def extract_napi_bindings(cpp):
    """binding name -> (function_id, full_name). Only mechanically exact rows."""
    calls_by_id = {c['id']: c for c in cpp['calls']}
    fns_by_name = {}
    for f in cpp['functions']:
        if not f['is_external']:
            fns_by_name.setdefault(f['name'], []).append(f)
    table, audit = {}, []
    for c in cpp['calls']:
        if c['name'] != 'Set' or c.get('receiver_name') != 'exports':
            continue
        if len(c['arguments']) < 2:
            continue
        a_name, a_fn = c['arguments'][0], c['arguments'][1]
        # arg0: Napi::String::New(env, "X") -> inner call whose last user arg is a CONSTANT
        name_lit = None
        inner = calls_by_id.get(a_name['value_ref']['id']) if a_name['value_ref']['kind'] == 'CALL' else None
        if inner and inner['name'] == 'New' and inner['arguments']:
            last = inner['arguments'][-1]
            if last['value_ref']['kind'] == 'CONSTANT':
                name_lit = (last['value_ref'].get('code') or '').strip().strip('"')
        # arg1: Napi::Function::New(env, Fn) -> inner call whose last user arg is a
        # METHOD_REF; the exporter carries its code (the function name).
        fn_name = None
        inner2 = calls_by_id.get(a_fn['value_ref']['id']) if a_fn['value_ref']['kind'] == 'CALL' else None
        if inner2 and inner2['name'] == 'New' and inner2['arguments']:
            fn_name = (inner2['arguments'][-1].get('code') or '').strip()
        if not name_lit or not fn_name:
            audit.append({'set_call': c['id'], 'skipped': 'shape not mechanically exact'})
            continue
        cands = fns_by_name.get(fn_name, [])
        if len(cands) != 1:
            audit.append({'set_call': c['id'], 'name': name_lit, 'fn': fn_name,
                          'skipped': f'{len(cands)} candidate functions (need exactly 1)'})
            continue
        table[name_lit] = (cands[0]['id'], cands[0]['full_name'])
        audit.append({'set_call': c['id'], 'name': name_lit, 'fn': fn_name,
                      'linked_function_id': cands[0]['id']})
    return table, audit

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('js_program'); ap.add_argument('cpp_program'); ap.add_argument('out')
    ap.add_argument('--js-receiver', default='bindings',
                    help='JS binding-object name whose method calls link to native (default: bindings)')
    a = ap.parse_args()
    js = json.load(open(a.js_program))
    cpp = json.load(open(a.cpp_program))

    table, audit = extract_napi_bindings(cpp)
    cpp = offset_ids(cpp)  # AFTER extraction (table holds pre-offset ids; offset below)

    linked, unlinked = [], []
    for c in js['calls']:
        if c.get('receiver_name') == a.js_receiver and c['resolution'] != 'EXACT':
            if c['name'] in table:
                fid, full = table[c['name']]
                c['resolution'] = 'EXACT'
                c['resolution_corrected'] = 'EXACT'
                c['candidate_target_ids'] = [fid + OFFSET]
                c['candidate_target_full_names'] = [full]
                c['resolution_reason'] = 'CROSS_LANGUAGE_NAPI_BINDING'
                linked.append({'js_call': c['id'], 'name': c['name'], 'cpp_function_id': fid + OFFSET})
            else:
                unlinked.append({'js_call': c['id'], 'name': c['name'],
                                 'reason': 'no mechanically exact registration'})

    merged = {'schema': js['schema'],
              'frontend': 'polyglot-composer(joern-jssrc2cpg+joern-c2cpg)',
              'metadata': js.get('metadata', []) + cpp.get('metadata', [])}
    for key in ('type_decls','members','functions','method_returns','locals','calls',
                'identifiers','returns','assignments'):
        merged[key] = js.get(key, []) + cpp.get(key, [])
    merged['frontend_counters'] = {k: js.get('frontend_counters', {}).get(k, 0)
                                       + cpp.get('frontend_counters', {}).get(k, 0)
                                   for k in set(js.get('frontend_counters', {})) | set(cpp.get('frontend_counters', {}))}
    if 'cpp_memory' in cpp: merged['cpp_memory'] = cpp['cpp_memory']
    if 'cpp_memory_locations' in cpp: merged['cpp_memory_locations'] = cpp['cpp_memory_locations']
    merged['cross_language_bindings'] = {
        'idiom': 'napi-exports-set', 'js_receiver': a.js_receiver, 'id_offset': OFFSET,
        'registrations': audit, 'linked_calls': linked, 'unlinked_calls': unlinked}
    json.dump(merged, open(a.out, 'w'), indent=1, sort_keys=True)
    print(f"POLYGLOT registrations={len(table)} linked_js_calls={len(linked)} unlinked={len(unlinked)}")

if __name__ == '__main__':
    main()
