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
call. The frontend DOES populate a different, real, structural field instead:
`receiver_type`, set (via the frontend's own type inference) to the exact string
argument of the `require(...)` call that initialized the receiver's local variable.
Matched against a small, curated, disclosed set of real, well-known native-addon-loading
conventions -- never a substring/loose match, same discipline as
`resource_contracts_r03.py`'s own qualifier-prefix fix. The OLD `receiver_name`/
`--js-receiver` check is kept, unchanged, as an alternative match (never removed) in case
some real, not-yet-observed JS/TS frontend path DOES populate it.

CROSSLANG-LINK-FIX01E (this revision -- see CHARACTERIZATION.md's own addendum for the
full, real account): FIX01B/D's own marker-regex approach (matching a `require(<quote>
<pkg><quote>):<returnValue>:` substring inside `candidate_target_full_names`) was ITSELF
shown to be source-formatting-fragile by direct testing through the real frontend --
a template-literal `require(\`pkg\`)`, internal whitespace (`require( 'pkg' )`, which
degrades `receiver_type` to `"ANY"` entirely), and an ALIASED two-statement loader
(`const f = require('pkg'); const native = f(x);`, where the marker never appears with
"require(" text at all -- `receiver_type` becomes `"pkg:<returnValue>"` directly instead)
each produced a DIFFERENT decision than the single-quoted chained case the regex was
built from, for four real, semantically-equivalent programs.

The real fix is `resolve_loader_provenance()` below: CANONICAL evidence derived from
walking real CPG node identity (call ids, `<operator>.assignment` records, argument node
ids) -- never parsing a serialized target-name/marker string. It asks, by ID: does the
receiver's own single, unambiguous assignment show its value came from INVOKING a call
whose callee is (directly, or through one bounded hop of variable aliasing) a real
`require(<literal-pkg>)` call, where the literal argument's OWN already quote-normalized
`code` field is read directly (sidestepping the quote-style problem entirely, since the
frontend normalizes a LITERAL's `code` to double quotes regardless of source style --
confirmed real across single/double/backtick source). Verified real and correct across
all four equivalence forms plus the original chained-call case (five real, independently
regenerated fixtures) and both real end-to-end corpus packages.

The OLD marker-regex (`_via_loader_invocation`/`_loader_invocation_pattern`) is KEPT, but
demoted to an explicitly labeled FALLBACK, tried ONLY when the canonical resolver cannot
establish provenance (e.g. genuinely ambiguous/duplicate assignments, or a receiver-
initialization shape the canonical walk does not (yet) model) -- never presented as
established evidence. Every linked call's own audit record carries which tier produced
it (`"canonical"` or `"fallback_marker_regex"`), so a reader can always tell them apart;
`link_napi_facts.py`'s own output never merges the two silently.
"""
import json, re, sys, argparse
from collections import defaultdict

# CROSSLANG-LINK-FIX01C: only packages CONFIRMED to export a directly-callable loader
# function -- `require(PKG)(args)` -- belong here. Confirmed real by reading each
# package's own published source (`module.exports = <function>`), not assumed:
#   - "bindings" (bindings@1.5.0: `module.exports = exports = bindings;`, a function)
#   - "node-gyp-build" (confirmed via real corpus usage, node-liblzma's own
#     `require('node-gyp-build')(bindingPath)`)
# REMOVED after review, disclosed here rather than silently dropped -- both were in an
# earlier version of this set WITHOUT the same per-package verification:
#   - "node-pre-gyp" / "@mapbox/node-pre-gyp": node-pre-gyp@0.17.0's real
#     lib/node-pre-gyp.js exports a plain OBJECT (`exports.find = ...`), NOT a callable
#     function. Real usage is `require('node-pre-gyp').find(path)` -- a method call on
#     the bare module, the same "helper, not the binding" shape this file exists to
#     reject -- then a SEPARATE `require(<dynamic path>)` this mechanism cannot resolve.
#   - "prebuild-install": CORRECTED, not what an earlier version of this comment said.
#     Absence of `main` does NOT mean unrequireable -- Node's own CommonJS resolution
#     defaults to the package root's `index.js`, and prebuild-install@7.1.3's real
#     index.js exists (`exports.download = require('./download')`). The real
#     disqualifying reason is the SAME export-shape issue as node-pre-gyp: an object
#     exposing an install-time `.download` HELPER, not a callable loader function.
# Matched by EXACT membership, never a substring -- an unrelated package whose name
# merely CONTAINS one of these (e.g. "some-bindings-helper") must NOT match; see
# study/crosslang_link_fix/controls for the real, run fixtures proving all of this.
NATIVE_LOADER_PACKAGES = {
    'bindings', 'node-gyp-build',
}
NATIVE_BUILD_PATH_MARKERS = ('build/Release/', 'build/Debug/')

# CROSSLANG-LINK-FIX01E: bounded hops of variable-to-variable aliasing the canonical
# resolver will walk (`const f = require(pkg); const g = f; const native = g(x);` is TWO
# hops) -- matches this project's own established bounded-trace discipline elsewhere
# (e.g. resource_guard_verdict_r04.py's backward_attacker_trace depth bound). Real corpus
# usage observed so far never exceeds one hop; kept slightly generous, still finite, so a
# genuinely unbounded/cyclic chain cannot hang this pass -- it simply exhausts the bound
# and correctly falls through to the fallback tier (or no match) instead.
LOADER_ALIAS_DEPTH = 3


def _strip_literal_quotes(code):
    """A JS/TS string LITERAL's own `code` field is quote-STYLE-NORMALIZED by the
    frontend to double quotes regardless of the real source's own quote character --
    confirmed real: `require('pkg')`, `require("pkg")`, and `` require(`pkg`) `` all
    produce a literal argument whose `code` is exactly `"pkg"`. Stripping the outer
    quote character here therefore recovers the real package name uniformly across every
    real quote style, with no per-style branching needed."""
    c = (code or '').strip()
    if len(c) >= 2 and c[0] == c[-1] and c[0] in ('"', "'", '`'):
        return c[1:-1]
    return c


class JsCallIndex:
    """Real, ID-keyed indices over a JS/TS program-facts doc's own `calls` list -- built
    once per run, consumed by `resolve_loader_provenance()`. No new export/frontend
    capability needed: every field used here (`id`, `name`, `code`, `arguments[].id`,
    `arguments[].kind`, `arguments[].code`) was already present in the existing schema."""

    def __init__(self, js):
        self.calls_by_id = {c['id']: c for c in js.get('calls', [])}
        self.assignments_by_lhs = defaultdict(list)
        self.require_calls = []  # [(call_id, pkg_name)]
        for c in js.get('calls', []):
            args = {a['index']: a for a in c.get('arguments', [])}
            if c.get('name') == '<operator>.assignment':
                lhs, rhs = args.get(1), args.get(2)
                if lhs and lhs.get('kind') == 'IDENTIFIER' and rhs:
                    self.assignments_by_lhs[lhs['code']].append(rhs)
            if c.get('name') == 'require':
                lit = args.get(1)
                if lit and lit.get('kind') == 'LITERAL':
                    self.require_calls.append((c['id'], _strip_literal_quotes(lit['code'])))


def _callee_resolves_to_require(invocation_call, idx, curated_packages, depth):
    """`invocation_call` is a real CALL node (looked up by id, not text) representing
    `X(...)` for some callee expression X. Returns the matched package name iff X --
    possibly through up to `depth` hops of single-assignment variable aliasing -- IS a
    real `require(pkg)` call for a curated `pkg`. Real, ID-based graph walk: every step
    looks up a call or assignment by its own node id, never by parsing a flattened
    target/marker string."""
    callee_name = invocation_call.get('name')
    # Case 1: X's own callee text is a require(pkg) call chained directly:
    # require(pkg)(...). The frontend represents a chained call's callee-expression text
    # as the OUTER call's own `name` field; a require call's own `code` is that same
    # text -- compared here as two already-computed, real fields on real nodes, not by
    # writing a quote/whitespace-aware pattern ourselves.
    for req_id, pkg in idx.require_calls:
        if pkg in curated_packages and callee_name == idx.calls_by_id[req_id].get('code'):
            return pkg
    if depth <= 0:
        return None
    # Case 2: X is a plain identifier -- an alias. Resolve its own single, unambiguous
    # assignment (real, disclosed abstention if the name has more than one real
    # assignment in the file -- genuinely ambiguous, not guessed at).
    next_assigns = idx.assignments_by_lhs.get(callee_name)
    if not next_assigns or len(next_assigns) != 1:
        return None
    next_rhs = next_assigns[0]
    if next_rhs.get('kind') != 'CALL':
        return None
    next_rhs_call = idx.calls_by_id.get(next_rhs['id'])
    if next_rhs_call is None:
        return None
    # Is the alias's OWN value directly require(pkg) (bare, unwrapped)? If so, CALLING
    # the alias (which is what got us here) IS invoking require(pkg) -- a real match.
    if next_rhs_call.get('name') == 'require':
        args = {a['index']: a for a in next_rhs_call.get('arguments', [])}
        lit = args.get(1)
        if lit and lit.get('kind') == 'LITERAL':
            pkg = _strip_literal_quotes(lit['code'])
            if pkg in curated_packages:
                return pkg
        return None
    # Otherwise the alias's own value is itself another invocation -- recurse, bounded.
    return _callee_resolves_to_require(next_rhs_call, idx, curated_packages, depth - 1)


def resolve_loader_provenance(receiver_name, idx, curated_packages, depth=LOADER_ALIAS_DEPTH):
    """CANONICAL evidence (see module docstring) that `receiver_name`'s value originates
    from INVOKING one of `curated_packages`. Returns (pkg, 'canonical') on proof, else
    (None, None) -- caller falls back to the explicitly-labeled, lower-confidence
    marker-regex heuristic. A receiver with zero or MORE THAN ONE real assignment in the
    file is a real abstention (ambiguous/shadowed), not a guess."""
    assigns = idx.assignments_by_lhs.get(receiver_name)
    if not assigns or len(assigns) != 1:
        return None, None
    rhs = assigns[0]
    if rhs.get('kind') != 'CALL':
        return None, None
    rhs_call = idx.calls_by_id.get(rhs['id'])
    if rhs_call is None:
        return None, None
    # receiver_name = rhs_call(...) -- receiver is the INVOCATION of rhs_call's own
    # callee. A BARE `receiver = require(pkg)` (rhs_call itself IS the require call, no
    # separate invocation wrapping it) is the loader-helper-itself case -- correctly NOT
    # a match here (confirmed real: this is exactly `const loader = require('node-gyp-
    # build'); loader.path(x)`'s own shape).
    if rhs_call.get('name') == 'require':
        return None, None
    pkg = _callee_resolves_to_require(rhs_call, idx, curated_packages, depth)
    return (pkg, 'canonical') if pkg else (None, None)


def _loader_invocation_pattern(pkg):
    # CROSSLANG-LINK-FIX01D: the frontend's <returnValue> marker preserves the source's
    # own quote character verbatim for the ONE real chained-call, single-line shape it
    # was built from -- accepts single or double quotes. CROSSLANG-LINK-FIX01E found this
    # itself does not generalize (template literals, whitespace, aliasing all produce a
    # DIFFERENT marker shape or none at all -- see module docstring) -- retained ONLY as
    # the explicitly-labeled fallback tier below, never as primary evidence.
    return re.compile(r"require\(['\"]" + re.escape(pkg) + r"['\"]\):<returnValue>:")


def _via_loader_invocation_fallback(call, pkg):
    """FALLBACK TIER ONLY -- see `resolve_loader_provenance()` for the canonical
    mechanism this is subordinate to, and the module docstring for why this regex does
    NOT generalize across real source-formatting variation. Kept for the narrow real
    cases the canonical, assignment-based walk cannot (yet) model (e.g. a receiver whose
    initializing assignment is not itself a simple `<operator>.assignment` this file's
    index captures) -- never presented as established evidence; every match through this
    path is tagged `"fallback_marker_regex"` in the output, not `"canonical"`."""
    pattern = _loader_invocation_pattern(pkg)
    targets = list(call.get('candidate_target_full_names') or []) + \
        list(call.get('canonical_targets') or [])
    return any(pattern.search(t) for t in targets)


def native_binding_receiver_evidence(call, idx):
    """Returns (matched: bool, tier: str|None) for whether `call`'s own receiver is a
    native-binding object. `tier` is `"canonical"` (the real, ID-based graph walk --
    tried FIRST, see below), `"fallback_marker_regex"` (only if canonical could not
    establish provenance), `"build_path"` for a direct build-path/`.node` match (no
    loader-invocation ambiguity to resolve -- a single require() step already IS the
    real module), or `None` if no match. None/empty `receiver_type` never matches for
    the build-path branch (fails closed) -- but does NOT gate the canonical walk, see
    below.

    CROSSLANG-LINK-FIX01E: the canonical resolver is tried FIRST, using the receiver's
    own identifier NAME (from `arguments[0]`), independent of what `receiver_type`
    itself says -- confirmed real and necessary: a whitespace-containing
    `require( 'pkg' )` degrades `receiver_type` to `"ANY"` entirely, even though the
    underlying `<operator>.assignment`/`require()` call graph this file's own index
    walks remains fully intact. Gating the canonical walk behind `receiver_type` would
    silently lose exactly the real cases it exists to recover. `receiver_type` is
    consulted only AFTER the canonical walk, for the build-path/`.node` branch (which
    has no analogous ambiguity) and as the fallback tier's own gate."""
    args = {a['index']: a for a in call.get('arguments', [])}
    a0 = args.get(0)
    receiver_name = a0['code'] if a0 and a0.get('kind') == 'IDENTIFIER' else None
    if receiver_name:
        pkg, tier = resolve_loader_provenance(receiver_name, idx, NATIVE_LOADER_PACKAGES)
        if pkg:
            return True, tier

    receiver_type = call.get('receiver_type')
    if not receiver_type:
        return False, None
    rt = receiver_type.strip()
    if rt.endswith('.node'):
        return True, 'build_path'
    if any(marker in rt for marker in NATIVE_BUILD_PATH_MARKERS):
        return True, 'build_path'
    if rt in NATIVE_LOADER_PACKAGES and _via_loader_invocation_fallback(call, rt):
        return True, 'fallback_marker_regex'
    return False, None


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
    js_index = JsCallIndex(js)

    linked, unlinked = [], []
    for c in js['calls']:
        # CROSSLANG-LINK-FIX01: a candidate is either the ORIGINAL --js-receiver name match
        # (kept, unchanged, never removed -- see module docstring) OR the new, real,
        # structural receiver_type match. Tried independently, same as R05's own "a call CAN
        # match via more than one path" discipline -- either one qualifies, never double-
        # counted (a call can only be linked/unlinked once per run, since it's visited once).
        receiver_matched, tier = native_binding_receiver_evidence(c, js_index)
        is_candidate = ((c.get('receiver_name') == a.js_receiver or receiver_matched)
                         and c['resolution'] != 'EXACT')
        if is_candidate:
            if c['name'] in table:
                fid, full = table[c['name']]
                c['resolution'] = 'EXACT'
                c['resolution_corrected'] = 'EXACT'
                c['candidate_target_ids'] = [fid + OFFSET]
                c['candidate_target_full_names'] = [full]
                c['resolution_reason'] = 'CROSS_LANGUAGE_NAPI_BINDING'
                linked.append({'js_call': c['id'], 'name': c['name'], 'cpp_function_id': fid + OFFSET,
                               'evidence_tier': tier or 'js_receiver_name'})
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
    n_canonical = sum(1 for l in linked if l['evidence_tier'] == 'canonical')
    n_fallback = sum(1 for l in linked if l['evidence_tier'] == 'fallback_marker_regex')
    print(f"POLYGLOT registrations={len(table)} linked_js_calls={len(linked)} "
          f"(canonical={n_canonical} fallback_regex={n_fallback} "
          f"other={len(linked) - n_canonical - n_fallback}) unlinked={len(unlinked)}")

if __name__ == '__main__':
    main()
