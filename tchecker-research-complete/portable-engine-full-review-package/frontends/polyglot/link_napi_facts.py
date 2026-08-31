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
    """Real, ID-keyed indices over a JS/TS program-facts doc's own `calls`/`functions`
    lists -- built once per run, consumed by `resolve_loader_provenance()`. No new
    export/frontend capability needed: every field used here (`id`, `name`, `code`,
    `full_name`, `parameters[].name`, `arguments[].id`, `arguments[].kind`,
    `arguments[].code`, `enclosing_function_id`) was already present in the existing
    schema."""

    def __init__(self, js):
        self.calls_by_id = {c['id']: c for c in js.get('calls', [])}
        self.functions_by_id = {f['id']: f for f in js.get('functions', [])}
        self.functions_by_full_name = {f['full_name']: f for f in js.get('functions', [])}
        # assignments_by_lhs: name -> [(rhs_arg, enclosing_function_id), ...] -- tracks
        # WHERE each real assignment lives, not just its value, so scope/shadowing can be
        # checked (see CROSSLANG-LINK-FIX01F, module docstring).
        self.assignments_by_lhs = defaultdict(list)
        self.require_calls = []  # [(call_id, pkg_name)]
        for c in js.get('calls', []):
            args = {a['index']: a for a in c.get('arguments', [])}
            if c.get('name') == '<operator>.assignment':
                lhs, rhs = args.get(1), args.get(2)
                if lhs and lhs.get('kind') == 'IDENTIFIER' and rhs:
                    self.assignments_by_lhs[lhs['code']].append(
                        (rhs, c.get('enclosing_function_id')))
            if c.get('name') == 'require':
                lit = args.get(1)
                if lit and lit.get('kind') == 'LITERAL':
                    self.require_calls.append((c['id'], _strip_literal_quotes(lit['code'])))

    def function_ancestor_chain(self, function_id):
        """Real, structural lexical-nesting chain for the function with this id, from
        OUTERMOST to the function itself -- derived from the frontend's own colon-
        separated `full_name` convention (confirmed real on a dedicated fixture: a
        function nested inside `outer` inside the top-level `program` gets full_name
        `"file::program:outer:inner"`, and EVERY successive colon-delimited prefix is
        itself a real function's own full_name in this schema). Returns [] if the
        function id is unknown or its full_name doesn't reconstruct cleanly -- callers
        treat that as "scope cannot be established safely" and abstain (fail closed),
        never as "no shadowing risk"."""
        func = self.functions_by_id.get(function_id)
        if func is None:
            return []
        full_name = func.get('full_name', '')
        if '::' not in full_name:
            return []
        file_part, rest = full_name.split('::', 1)
        segments = rest.split(':')
        chain = []
        prefix = file_part + '::'
        for i, seg in enumerate(segments):
            prefix = prefix + seg if i == 0 else prefix + ':' + seg
            f = self.functions_by_full_name.get(prefix)
            if f is None:
                return []
            chain.append(f)
        return chain

    def receiver_definition(self, receiver_name, enclosing_function_id):
        """CROSSLANG-LINK-FIX01F -- see module docstring for the full, real account of
        why this exists. Returns (rhs_arg, None) for the single, unambiguous,
        correctly-in-scope, unshadowed real definition of `receiver_name` reaching a
        use inside the function identified by `enclosing_function_id`, or (None,
        reason) with an explicit, disclosed abstention reason otherwise -- never a
        guess. `reason` is one of:
          NO_DEFINITION, MULTIPLE_DEFINITIONS_AMBIGUOUS (more than one real
          `<operator>.assignment` to this name anywhere in the file -- reassignment,
          branch-multi-definition, or genuine ambiguity are all indistinguishable
          without real CFG/execution-order data, which this schema does not export, so
          ALL are treated alike: abstain, never guess which one "wins"),
          SCOPE_UNRESOLVED (the call's or the definition's own function context could
          not be reconstructed via `function_ancestor_chain` -- fails closed),
          DEFINITION_NOT_IN_SCOPE (the found assignment's own function is not a real
          lexical ancestor of the call's function, nor the call's function itself -- an
          unrelated/sibling scope's same-named variable, not a real closure capture),
          PARAMETER_SHADOWED (some function strictly between the definition's own scope
          and the call's scope, inclusive of the call's own function, declares a
          PARAMETER with this exact name -- that parameter binds first at the call
          site, and its real value cannot be established statically; confirmed real and
          necessary via a dedicated fixture, see CHARACTERIZATION.md)."""
        assigns = self.assignments_by_lhs.get(receiver_name)
        if not assigns:
            return None, 'NO_DEFINITION'
        if len(assigns) > 1:
            return None, 'MULTIPLE_DEFINITIONS_AMBIGUOUS'
        rhs, def_function_id = assigns[0]
        call_chain = self.function_ancestor_chain(enclosing_function_id)
        def_func = self.functions_by_id.get(def_function_id)
        if not call_chain or def_func is None:
            return None, 'SCOPE_UNRESOLVED'
        def_full_name = def_func.get('full_name')
        def_index = next((i for i, f in enumerate(call_chain)
                           if f.get('full_name') == def_full_name), None)
        if def_index is None:
            return None, 'DEFINITION_NOT_IN_SCOPE'
        for f in call_chain[def_index + 1:]:
            for p in f.get('parameters', []):
                if p.get('name') == receiver_name:
                    return None, 'PARAMETER_SHADOWED'
        return rhs, None


def _callee_resolves_to_require(invocation_call, idx, curated_packages, depth):
    """`invocation_call` is a real CALL node (looked up by id, not text) representing
    `X(...)` for some callee expression X, invoked from WITHIN
    `invocation_call['enclosing_function_id']`'s own scope. Returns the matched package
    name iff X -- possibly through up to `depth` hops of single-assignment variable
    aliasing -- IS a real `require(pkg)` call for a curated `pkg`. Real, ID-based graph
    walk: every step looks up a call or assignment by its own node id, never by parsing
    a flattened target/marker string. Every alias hop goes through the SAME
    `JsCallIndex.receiver_definition()` scope/shadowing check as the top-level receiver
    (CROSSLANG-LINK-FIX01F) -- an alias is exactly as capable of being ambiguously
    reassigned or parameter-shadowed as the receiver itself, and was NOT checked this
    way before that fix; confirmed real and necessary, not merely theoretical, since
    real corpus code (`node-liblzma`) uses exactly this one-hop-alias shape."""
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
    # Case 2: X is a plain identifier -- an alias. Resolve its own single, unambiguous,
    # in-scope, unshadowed definition (real abstention -- not a guess -- on ambiguity,
    # unresolved scope, or shadowing; see receiver_definition's own docstring).
    next_rhs, reason = idx.receiver_definition(
        callee_name, invocation_call.get('enclosing_function_id'))
    if next_rhs is None or next_rhs.get('kind') != 'CALL':
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


def resolve_loader_provenance(receiver_name, enclosing_function_id, idx, curated_packages,
                                depth=LOADER_ALIAS_DEPTH):
    """CANONICAL evidence (see module docstring) that `receiver_name`'s value, AS SEEN
    FROM WITHIN `enclosing_function_id`'s own scope, originates from INVOKING one of
    `curated_packages`. Returns (pkg, 'canonical') on proof, else (None, reason) --
    `reason` is one of `JsCallIndex.receiver_definition`'s own disclosed abstention
    codes, or `'NOT_AN_INVOCATION'`/`'BARE_LOADER_REFERENCE'`/`'CALLEE_NOT_REQUIRE'` for
    a real, in-scope, unambiguous definition whose value simply isn't a loader
    invocation. Caller falls back to the explicitly-labeled, lower-confidence
    marker-regex heuristic ONLY when a real reason is returned here, never presented as
    silently equivalent to a genuine non-match."""
    rhs, reason = idx.receiver_definition(receiver_name, enclosing_function_id)
    if rhs is None:
        return None, reason
    if rhs.get('kind') != 'CALL':
        return None, 'NOT_AN_INVOCATION'
    rhs_call = idx.calls_by_id.get(rhs['id'])
    if rhs_call is None:
        return None, 'NOT_AN_INVOCATION'
    # receiver_name = rhs_call(...) -- receiver is the INVOCATION of rhs_call's own
    # callee. A BARE `receiver = require(pkg)` (rhs_call itself IS the require call, no
    # separate invocation wrapping it) is the loader-helper-itself case -- correctly NOT
    # a match here (confirmed real: this is exactly `const loader = require('node-gyp-
    # build'); loader.path(x)`'s own shape).
    if rhs_call.get('name') == 'require':
        return None, 'BARE_LOADER_REFERENCE'
    pkg = _callee_resolves_to_require(rhs_call, idx, curated_packages, depth)
    return (pkg, 'canonical') if pkg else (None, 'CALLEE_NOT_REQUIRE')


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
    """Returns (matched: bool, tier: str|None, reason: str|None) for whether `call`'s
    own receiver is a native-binding object. `tier` is `"canonical"` (the real,
    ID-based, scope-checked graph walk -- tried FIRST, see below),
    `"fallback_marker_regex"` (tried ONLY when canonical established a real, safe,
    unambiguous, unshadowed receiver definition but could not itself prove that
    definition's value is a loader invocation -- see below), `"build_path"` for a
    direct build-path/`.node` match (no loader-invocation ambiguity to resolve -- a
    single require() step already IS the real module), or `None` if no match. When
    `matched` is False and `tier` is None, `reason` carries the real, disclosed
    abstention code (from `JsCallIndex.receiver_definition`/`resolve_loader_provenance`)
    -- an explicit reason, never a silent non-match indistinguishable from "not a
    candidate at all".

    CROSSLANG-LINK-FIX01E: the canonical resolver is tried FIRST, using the receiver's
    own identifier NAME (from `arguments[0]`), independent of what `receiver_type`
    itself says -- confirmed real and necessary: a whitespace-containing
    `require( 'pkg' )` degrades `receiver_type` to `"ANY"` entirely, even though the
    underlying `<operator>.assignment`/`require()` call graph this file's own index
    walks remains fully intact.

    CROSSLANG-LINK-FIX01F: the fallback regex is now gated behind the SAME real
    scope/ambiguity check the canonical resolver uses, not tried independently --
    confirmed real and necessary: without this gate, a receiver reassigned after its
    real `require()` call, or defined differently in two branches, still carried the
    OLD `<returnValue>` marker text from its real-but-superseded (or merely one-of-
    several-possible) definition, so the fallback alone would WRONGLY link a call whose
    receiver's actual value at that point is NOT the native binding -- confirmed on
    dedicated overwrite-before-use and branch-multi-definition fixtures, see
    CHARACTERIZATION.md. The fallback is now reached ONLY when `resolve_loader_
    provenance` returns the specific `'CALLEE_NOT_REQUIRE'` reason -- meaning the
    receiver's OWN identity is already established as real, single, in-scope, and
    unshadowed; only the shape of ITS OWN value could not be canonically proven to be a
    loader invocation. Every other abstention reason (ambiguous, shadowed, unresolved,
    out of scope, or a bare unwrapped loader reference) is a hard rejection -- the
    fallback never gets a chance to override it."""
    args = {a['index']: a for a in call.get('arguments', [])}
    a0 = args.get(0)
    receiver_name = a0['code'] if a0 and a0.get('kind') == 'IDENTIFIER' else None
    reason = None
    if receiver_name:
        pkg, reason = resolve_loader_provenance(
            receiver_name, call.get('enclosing_function_id'), idx, NATIVE_LOADER_PACKAGES)
        if pkg:
            return True, 'canonical', None
        if reason == 'CALLEE_NOT_REQUIRE':
            receiver_type = call.get('receiver_type')
            rt = receiver_type.strip() if receiver_type else ''
            if rt in NATIVE_LOADER_PACKAGES and _via_loader_invocation_fallback(call, rt):
                return True, 'fallback_marker_regex', None

    receiver_type = call.get('receiver_type')
    if not receiver_type:
        return False, None, reason
    rt = receiver_type.strip()
    if rt.endswith('.node'):
        return True, 'build_path', None
    if any(marker in rt for marker in NATIVE_BUILD_PATH_MARKERS):
        return True, 'build_path', None
    return False, None, reason


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

    # CROSSLANG-LINK-FIX01F: real, explicit abstention reasons that mean a receiver's
    # identity itself was genuinely at risk (reassignment, branching, shadowing,
    # unresolved/out-of-scope definitions, or a proven-bare unwrapped loader reference)
    # are recorded here for audit -- never silently indistinguishable from "not a
    # loader-shaped name at all" (`NO_DEFINITION`, the overwhelming majority of
    # unrelated real calls, which is not logged as it carries no real signal).
    #
    # `resolve_loader_provenance` runs for EVERY call with an identifier receiver, not
    # only loader-shaped ones (needed so the whitespace-degraded-`receiver_type` case
    # is still caught -- see `native_binding_receiver_evidence`'s own docstring), so
    # most real abstentions (a same-named variable reassigned or shadowed for reasons
    # that have nothing to do with native bindings) carry no real audit signal -- logging
    # ALL of them was confirmed, on real corpus data, to swamp the audit trail (220 real
    # entries for node-liblzma alone, nearly all unrelated). Logging is therefore further
    # restricted to calls whose OWN `receiver_type` is at least PLAUSIBLY loader-related:
    # a curated loader package name, a build-path/`.node` shape, or the degraded `"ANY"`
    # this project's own whitespace-fixture confirmed can still hide a real loader use.
    NOTABLE_ABSTENTION_REASONS = {
        'MULTIPLE_DEFINITIONS_AMBIGUOUS', 'PARAMETER_SHADOWED', 'SCOPE_UNRESOLVED',
        'DEFINITION_NOT_IN_SCOPE', 'BARE_LOADER_REFERENCE', 'CALLEE_NOT_REQUIRE',
    }

    def _plausibly_loader_related(receiver_type):
        if not receiver_type:
            return False
        rt = receiver_type.strip()
        return (rt == 'ANY' or rt in NATIVE_LOADER_PACKAGES or rt.endswith('.node')
                or any(marker in rt for marker in NATIVE_BUILD_PATH_MARKERS))

    linked, unlinked, abstained = [], [], []
    for c in js['calls']:
        # CROSSLANG-LINK-FIX01: a candidate is either the ORIGINAL --js-receiver name match
        # (kept, unchanged, never removed -- see module docstring) OR the new, real,
        # structural receiver_type match. Tried independently, same as R05's own "a call CAN
        # match via more than one path" discipline -- either one qualifies, never double-
        # counted (a call can only be linked/unlinked once per run, since it's visited once).
        receiver_matched, tier, reason = native_binding_receiver_evidence(c, js_index)
        is_candidate = ((c.get('receiver_name') == a.js_receiver or receiver_matched)
                         and c['resolution'] != 'EXACT')
        if reason in NOTABLE_ABSTENTION_REASONS and _plausibly_loader_related(c.get('receiver_type')):
            abstained.append({'js_call': c['id'], 'name': c['name'], 'reason': reason,
                              'receiver_type': c.get('receiver_type')})
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
        'registrations': audit, 'linked_calls': linked, 'unlinked_calls': unlinked,
        'abstained_calls': abstained}
    json.dump(merged, open(a.out, 'w'), indent=1, sort_keys=True)
    n_canonical = sum(1 for l in linked if l['evidence_tier'] == 'canonical')
    n_fallback = sum(1 for l in linked if l['evidence_tier'] == 'fallback_marker_regex')
    print(f"POLYGLOT registrations={len(table)} linked_js_calls={len(linked)} "
          f"(canonical={n_canonical} fallback_regex={n_fallback} "
          f"other={len(linked) - n_canonical - n_fallback}) unlinked={len(unlinked)} "
          f"abstained={len(abstained)}")

if __name__ == '__main__':
    main()
