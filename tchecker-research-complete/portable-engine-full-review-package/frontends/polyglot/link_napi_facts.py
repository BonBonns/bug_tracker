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

CROSSLANG-LINK-FIX01 (see study/crosslang_link_fix/CHARACTERIZATION.md for the full,
real, quantitative account): the original JS-side candidate filter
(`c.get('receiver_name') == a.js_receiver`, default "bindings") never matched ANY real
call across the whole frozen 494-package corpus -- 0 linked_calls, 0 unlinked_calls,
even for the 163 real packages where the C/C++ side above successfully found 1,119 real
`exports.Set(...)` registrations. Root cause, confirmed on two independent real packages
by regenerating and reading their real JS facts directly: the JS/TS frontend's own
`receiver_name` field is essentially NEVER populated for a real native-binding member
call (confirmed: 0 non-null values across 1,099 real calls in `memoryjs`, 0 across 3,672
in `node-liblzma`) -- so no `--js-receiver` value, however chosen, could ever have
matched real code. The frontend DOES populate a different, real, structural field
instead: `receiver_type`, set (via the frontend's own type inference) to the exact string
argument of the `require(...)` call that initialized the receiver's local variable --
confirmed real: `const memoryjs = require('./build/Release/memoryjs')` gives
`receiver_type: "build/Release/memoryjs"`; `const liblzma =
require('node-gyp-build')(bindingPath)` gives `receiver_type: "node-gyp-build"` (the
OUTER require's argument, even through one level of call-chaining) -- and real downstream
calls (`liblzma.isXZ(...)`, `memoryjs.openProcess(...)`) carry that SAME `receiver_type`,
with `resolution: "HEURISTIC"` (not yet `"EXACT"`), exactly matching this file's own
existing `c['resolution'] != 'EXACT'` candidate condition. `is_native_binding_receiver()`
below matches on THIS field instead, against a small, curated, disclosed set of
real, well-known native-addon-loading conventions -- never a substring/loose match, same
discipline as `resource_contracts_r03.py`'s own qualifier-prefix fix. The OLD
`receiver_name`/`--js-receiver` check is kept, unchanged, as an alternative match (never
removed) in case some real, not-yet-observed JS/TS frontend path DOES populate it.
"""
import json, sys, argparse

# Real, curated, disclosed native-addon-loading conventions -- confirmed against real
# require() targets in two independent real corpus packages (see module docstring).
# Matched by EXACT membership/prefix, never a substring -- an unrelated package whose name
# merely CONTAINS one of these (e.g. "some-bindings-helper") must NOT match; see
# study/crosslang_link_fix/controls for the real, run fixture proving this.
NATIVE_LOADER_PACKAGES = {
    'bindings', 'node-gyp-build', 'node-pre-gyp', '@mapbox/node-pre-gyp',
    'prebuild-install',
}
NATIVE_BUILD_PATH_MARKERS = ('build/Release/', 'build/Debug/')


def _via_loader_invocation(call, pkg):
    """CROSSLANG-LINK-FIX01B (real boundary control, see module docstring and
    study/crosslang_link_fix/CHARACTERIZATION.md's own addendum): for a LOADER-PACKAGE
    receiver_type (e.g. "node-gyp-build"), `receiver_type` alone is NOT enough -- confirmed
    real and ambiguous: `const loader = require('node-gyp-build'); loader.path(x)` (a call
    on the loader HELPER itself, never invoked) carries the SAME receiver_type as
    `const native = require('node-gyp-build')(x); native.Bar()` (the loader actually
    INVOKED, producing the real native binding). The frontend's own resolution DOES
    structurally distinguish them, though: only the invoked case's `candidate_target_
    full_names`/`canonical_targets` contains a `require('<pkg>'):<returnValue>:` marker
    (confirmed real on both node-liblzma's real `isXZ` call and a dedicated boundary
    fixture) -- the bare, non-invoked loader reference never does. This checks for exactly
    that marker, scoped to the SAME package name matched via receiver_type -- never a bare
    "any <returnValue> marker", which could in principle belong to an unrelated require()."""
    marker = f"require('{pkg}'):<returnValue>:"
    targets = list(call.get('candidate_target_full_names') or []) + \
        list(call.get('canonical_targets') or [])
    return any(marker in t for t in targets)


def is_native_binding_receiver(call):
    """True iff `call`'s own `receiver_type` (a JS/TS local's own resolved type, per the
    frontend's type inference over its `require(...)` initializer -- see module docstring)
    matches a real, curated native-addon-loading convention. None/empty never matches
    (fails closed, same as every other abstention in this project). Matched by EXACT set
    membership for loader package names (never a substring -- "some-bindings-helper" must
    not match "the 'bindings' package") and by substring only for the two fixed, meaningful
    node-gyp output path segments, which are real, unambiguous directory names, not bare
    words. For a loader-PACKAGE match specifically, ALSO requires `_via_loader_invocation`
    evidence that the loader was actually CALLED (not just referenced) -- see that
    function's own docstring for the real ambiguity this guards against. No such extra
    requirement for a build-path/`.node` match: a direct `require('./build/Release/x')`
    already IS the real module in one step, with no separate "helper vs. invoked result"
    distinction to guard."""
    receiver_type = call.get('receiver_type')
    if not receiver_type:
        return False
    rt = receiver_type.strip()
    if rt in NATIVE_LOADER_PACKAGES:
        return _via_loader_invocation(call, rt)
    if rt.endswith('.node'):
        return True
    return any(marker in rt for marker in NATIVE_BUILD_PATH_MARKERS)

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
        # CROSSLANG-LINK-FIX01: a candidate is either the ORIGINAL --js-receiver name match
        # (kept, unchanged, never removed -- see module docstring) OR the new, real,
        # structural receiver_type match. Tried independently, same as R05's own "a call CAN
        # match via more than one path" discipline -- either one qualifies, never double-
        # counted (a call can only be linked/unlinked once per run, since it's visited once).
        is_candidate = ((c.get('receiver_name') == a.js_receiver
                          or is_native_binding_receiver(c))
                         and c['resolution'] != 'EXACT')
        if is_candidate:
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
