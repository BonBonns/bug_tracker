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
it, so a reader can always tell them apart; `link_napi_facts.py`'s own output never
merges tiers silently.

CROSSLANG-LINK-FIX01G (this revision -- see CHARACTERIZATION.md's own addendum for the
full, real account): FIX01F's own "exactly one real assignment, in a real lexical
ancestor scope, not parameter-shadowed" rule -- now called SCOPE_UNIQUE, since that is
precisely and only what it establishes -- was shown, by direct testing through the real
frontend on four dedicated adversarial fixtures, to say NOTHING about EXECUTION ORDER:
a scope-unique definition inside a single `if` branch with no `else`, inside a `for`
loop body, inside a `try` block (no corresponding assignment on the `catch` path), or
positioned in the source AFTER a synchronous call that already reaches the use, is
indistinguishable from a genuinely safe unconditional definition under SCOPE_UNIQUE
alone -- confirmed real: all four cases were WRONGLY accepted before this fix.

First checked whether jssrc2cpg's own CPG contains usable CFG structure even though the
JS/TS exporter had never surfaced it: confirmed real via direct Joern-REPL query
(`call.outE("CFG").l` / `.cfgNext` returned real edges). `export_neutral.sc` and
`normalize_joern_facts.py` were extended (mirroring the C/C++ side's own
`export_c_cpp_facts_v03.sc` `cfg_edges.tsv` convention exactly) to surface `cfg_edges`
(owner/from/to) and `method_cfg_endpoints` (method_id/entry_id/exit_id, using Joern's own
Method-node-as-entry / MethodReturn-as-exit convention) in the normalized JS facts doc.

The FIX01G design accepted a SCOPE_UNIQUE definition as loader provenance if (a) the
assignment dominated its own defining function's real exit node (methodReturn; rules out
one-branch-only, loop-only, and try/catch-only assignments), AND (b), only when the use
lived in a DIFFERENT function than the assignment, the assignment additionally dominated
every real, direct, same-defining-scope call invoking the use's function. All four new
adversarial fixtures at the time (assignment-after-use, one-branch-only, loop-only,
try/catch-only) correctly abstained under this design.

CROSSLANG-LINK-FIX01H (this revision -- see CHARACTERIZATION.md's own addendum for the
full, real account): FIX01G's own check (a) was ITSELF a real overclaim for the
cross-function case -- caught by direct review, not by a failing fixture. "The
assignment dominates its own function's exit" is a real, meaningful CFG fact ONLY within
that ONE function's own CFG. It proves NOTHING about a node inside a DIFFERENT function's
own, separate CFG -- there is no single graph in which "dominance" across two different
functions is even a well-formed question. FIX01G's cross-function branch silently
treated exit-dominance as if it answered that question anyway. Concretely, this let the
single most common real native-addon pattern through on CFG grounds that do not actually
apply to it:

    const native = require("node-gyp-build")(__dirname);
    function wrapper() { return native.Foo(); }

`native`'s assignment does dominate the top-level module's own exit -- but that is a fact
about the MODULE's CFG, and `wrapper`'s body is a different function with its own,
separate CFG that the assignment node does not even belong to. Whether this pattern is
safe is real, but it is NOT a CFG-dominance fact -- it depends on JS closure semantics
(the capture is real and, if the binding is `const`, immutable) that CFG dominance alone
cannot express.

Fixed by `loader_definition_reaches_use()` below, which never conflates the two claims.
SAME-function assignment/use (real dominance is meaningful): checked directly against
the SPECIFIC use node via `cfg_dominates`, not a function-exit proxy -- tagged
`"dominance_proven"`. CROSS-function assignment/use: CFG dominance is NEVER attempted;
REAL, SEPARATE closure-capture evidence is required instead, and missing or
cross-function CFG evidence always abstains rather than silently falling back to
SCOPE_UNIQUE alone. All of: (a) the assignment is a real `const` declaration (JS
language-enforced immutability of the binding -- read directly off the assignment's own
`code` field, e.g. `"const native = require(...)"`, confirmed real via REPL); (b) Joern's
OWN real closure-binding evidence (`Local.closureBindingId`, confirmed real via REPL on a
dedicated closure fixture: a nested function's own use of an outer name gets a dedicated
LOCAL node owned by the NESTED function, and every real IDENTIFIER use inside it
`refsTo` THAT local, not the outer one -- a different, STRONGER claim than mere lexical
ancestry) proves `receiver_name` is really captured by the use's function; (c) the
assignment dominates its OWN defining function's real exit (the module-load-then-export
contract: an external caller cannot invoke an exported closure before the whole module
has finished loading); (d) any real, direct, same-defining-scope invocation of the use's
function is ALSO dominated by the assignment (still catches assignment-after-use within
the same scope). Tagged `"closure_capture_proven"` -- a DIFFERENT, explicitly weaker tier
name than `"dominance_proven"`, never merged with it.

The `CALLEE_NOT_REQUIRE` abstention reason -- the ONLY reason the marker-regex fallback
is ever tried -- can still only be reached AFTER this gate has already passed (same-
function OR cross-function), so the fallback tier remains automatically subject to the
identical gate with no separate plumbing. Verified real and correct: the module-level
`const` example above is now correctly `closure_capture_proven`; the four FIX01G
adversarial fixtures remain correctly rejected; the full existing control suite and both
real end-to-end corpus packages (`memoryjs`, `node-liblzma`) re-verified with zero
regressions, re-run through the extended exporter so real `cfg_edges`/
`method_cfg_endpoints`/`locals` (with closure-binding ids) data is present.

CROSSLANG-LINK-FIX01I (this revision -- see CHARACTERIZATION.md's own addendum for the
full, real account): two further, real soundness gaps in FIX01H's own closure-capture
evidence, found by direct review, not by a spontaneously-failing fixture:

1. `_is_const_declaration` proves the BINDING cannot be REASSIGNED; it proves NOTHING
   about which VALUE initialized it. `const native = flag ? require(pkg)(...) : fake;`
   passes every FIX01H check unchanged -- and confirmed real via Joern-REPL that this is
   not merely theoretical: jssrc2cpg's own type-recovery pass can silently resolve the
   ternary's `receiver_type` to the LOADER branch's type alone, discarding `fake`
   entirely, meaning the marker-regex fallback could have matched right through this
   design's own dominance/closure gates (which check WHERE the assignment reaches, never
   WHAT value it evaluates to). Fixed by `_is_unconditional_invocation_shape()`: the
   assignment's RHS call's own `name` field is checked against the real, structural
   `"<operator>."` prefix convention (a ternary's own name is exactly
   `"<operator>.conditional"`, confirmed via REPL) -- rejected with
   `'INITIALIZER_NOT_UNCONDITIONAL'` BEFORE `_callee_resolves_to_require` is ever tried,
   so the fallback (gated behind `'CALLEE_NOT_REQUIRE'` specifically) can never be
   reached for this shape either. Applied identically to the top-level receiver and
   every alias hop.

2. FIX01H's own invocation-dominance check (part d) only looked for DIRECT
   `wrapper()` calls whose own `candidate_target_ids` resolves to the closure function --
   blind to the closure function being PASSED AS A VALUE to something else
   (`invoke(wrapper)`), assigned, exported, or returned, BEFORE the capturing assignment
   runs. Any of these "escapes" can result in the closure being invoked, via whatever
   received the reference, at an uncontrolled later time with no guarantee the
   assignment has run yet. Fixed by `escape_sites()`: every real IDENTIFIER reference to
   the closure function's own declared name within the defining scope -- confirmed real
   via Joern-REPL that `invoke(wrapper)` produces a real IDENTIFIER node for `wrapper`,
   indistinguishable in kind from any other identifier reference, EXCLUDING the
   function's own hoisted declaration LHS (`_declaration_lhs_identifier_id`) -- must
   ALSO be dominated by the assignment, added as requirement (e) alongside (a)-(d).

Verified real and correct on a new, dedicated fixture
(`controls/const_cross_function_escape_probe`, four cases matching a direct review
request): a conditional loader-versus-fake initializer now correctly abstains
(`INITIALIZER_NOT_UNCONDITIONAL`); a callback passed to another function BEFORE
initialization now correctly abstains (`CROSS_FUNCTION_ESCAPE_NOT_DOMINATED`); the SAME
callback registration pattern AFTER initialization is correctly ACCEPTED
(`closure_capture_proven`), confirming the new check does not over-reject the safe,
common case; exporting/assigning the wrapper BEFORE initialization now correctly
abstains. The full existing control suite, both real end-to-end corpus packages, and all
three prior adversarial fixtures re-verified with zero regressions.
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


def _cfg_reachable(cfg_next, start_id, target_id, avoid=None):
    """CROSSLANG-LINK-FIX01G: real, bounded BFS reachability from `start_id` to
    `target_id` over `cfg_next` (a real CFG-successor adjacency map, node id -> [node
    id, ...], built from the frontend's own `cfg_edges` export). `avoid`, if given, is
    treated as removed from the graph for this walk only (a temporary BFS-time
    exclusion, never a persistent mutation of `cfg_next` itself) -- the standard
    node-removal dominance test's own reachability sub-step. `visited` bounds the walk
    to the real, finite node count, so a genuine CFG cycle (a loop) cannot hang this."""
    if start_id == target_id:
        return True
    seen = {start_id}
    stack = [start_id]
    while stack:
        n = stack.pop()
        for nxt in cfg_next.get(n, ()):
            if nxt == target_id:
                return True
            if nxt == avoid or nxt in seen:
                continue
            seen.add(nxt)
            stack.append(nxt)
    return False


def cfg_dominates(cfg_next, entry_id, dom_id, target_id):
    """CROSSLANG-LINK-FIX01G: real, structural CFG dominance -- does EVERY real path
    from `entry_id` to `target_id` pass through `dom_id`? Computed by the standard
    node-removal test: `target_id` is reachable from `entry_id` in the real graph
    (else there is nothing to prove either way), then `dom_id` is temporarily excluded
    and reachability is re-checked -- if `target_id` is STILL reachable without
    `dom_id`, `dom_id` does not dominate it. Returns True (proven dominant), False
    (proven NOT dominant), or None ("cannot establish" -- `target_id` is not reachable
    from `entry_id` at all, usually a real id mismatch or genuinely dead code, never
    silently treated as a pass by any caller in this file)."""
    if not _cfg_reachable(cfg_next, entry_id, target_id):
        return None
    if dom_id == target_id:
        return True
    return not _cfg_reachable(cfg_next, entry_id, target_id, avoid=dom_id)


class JsCallIndex:
    """Real, ID-keyed indices over a JS/TS program-facts doc's own `calls`/`functions`
    lists -- built once per run, consumed by `resolve_loader_provenance()`. Every field
    used here (`id`, `name`, `code`, `full_name`, `parameters[].name`, `arguments[].id`,
    `arguments[].kind`, `arguments[].code`, `enclosing_function_id`) was already present
    in the existing schema; `cfg_edges`/`method_cfg_endpoints` (CROSSLANG-LINK-FIX01G)
    are new, real fields added to the JS/TS exporter for this fix -- absent (empty) on
    an older raw export, which then fails CLOSED on every dominance check below
    (`CFG_UNAVAILABLE`), never silently passes one."""

    def __init__(self, js):
        self.calls_by_id = {c['id']: c for c in js.get('calls', [])}
        self.functions_by_id = {f['id']: f for f in js.get('functions', [])}
        self.functions_by_full_name = {f['full_name']: f for f in js.get('functions', [])}
        # assignments_by_lhs: name -> [(rhs_arg, enclosing_function_id, assign_call_id),
        # ...] -- tracks WHERE each real assignment lives (for scope/shadowing,
        # CROSSLANG-LINK-FIX01F) and its OWN CFG node id (for dominance,
        # CROSSLANG-LINK-FIX01G: the `<operator>.assignment` call's own id IS the real
        # CFG node representing "this assignment has executed").
        self.assignments_by_lhs = defaultdict(list)
        self.require_calls = []  # [(call_id, pkg_name)]
        for c in js.get('calls', []):
            args = {a['index']: a for a in c.get('arguments', [])}
            if c.get('name') == '<operator>.assignment':
                lhs, rhs = args.get(1), args.get(2)
                if lhs and lhs.get('kind') == 'IDENTIFIER' and rhs:
                    self.assignments_by_lhs[lhs['code']].append(
                        (rhs, c.get('enclosing_function_id'), c['id']))
            if c.get('name') == 'require':
                lit = args.get(1)
                if lit and lit.get('kind') == 'LITERAL':
                    self.require_calls.append((c['id'], _strip_literal_quotes(lit['code'])))

        # CROSSLANG-LINK-FIX01G: cfg_next (node id -> [next node id, ...]) and
        # method_exit (method/function id -> its real methodReturn node id), both built
        # from the frontend's own real `cfg_edges`/`method_cfg_endpoints` export.
        self.cfg_next = defaultdict(list)
        for e in js.get('cfg_edges', []):
            self.cfg_next[e['from']].append(e['to'])
        self.method_exit = {ep['method_id']: ep['exit_id']
                             for ep in js.get('method_cfg_endpoints', [])}
        # CROSSLANG-LINK-FIX01G addendum: real ids of calls AST-nested inside a `try`
        # block -- see `loader_definition_reaches_use()`'s own docstring for why CFG
        # dominance alone is not sound for these (jssrc2cpg's CFG does not model an
        # implicit exceptional edge into `catch`, confirmed real on a dedicated fixture).
        self.try_nested_calls = set(js.get('try_nested_calls', []))

        # CROSSLANG-LINK-FIX01H: real closure-binding evidence, keyed exactly as Joern
        # itself formats `closureBindingId` (`"<capturing-function-full-name>:<captured-
        # variable-name>"`, confirmed real via direct Joern-REPL query -- see
        # `has_closure_binding_evidence()`'s own docstring). This is Joern's OWN
        # structural proof that a nested function's own use of a name is a real closure
        # capture of an outer binding, not merely a same-named identifier reachable via
        # lexical-ancestry name lookup (which `function_ancestor_chain`/
        # `receiver_definition` above establish, and which is a DIFFERENT, weaker claim).
        self.closure_binding_keys = {
            loc['closure_binding_id'] for loc in js.get('locals', [])
            if loc.get('closure_binding_id')
        }

        # CROSSLANG-LINK-FIX01I: real, per-scope IDENTIFIER occurrences, for escape-site
        # detection in `escape_sites()` below -- every real reference to a captured
        # closure FUNCTION's own name (an argument passed to some other call, the RHS of
        # an assignment, a return value, an export -- any occurrence at all, not only a
        # direct `wrapper()` call) shows up here, confirmed real via direct Joern-REPL
        # query: `invoke(wrapper)` produces a real IDENTIFIER node for `wrapper`, owned
        # by the SAME enclosing method as the call, indistinguishable in kind from any
        # other identifier reference.
        self.identifiers_by_method = defaultdict(list)
        for ident in js.get('identifiers', []):
            self.identifiers_by_method[ident.get('method_id')].append(ident)

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
        """CROSSLANG-LINK-FIX01F/G/H -- see module docstring for the full, real account
        of why this exists. Establishes SCOPE_UNIQUE reaching-definition evidence ONLY --
        real dominance-or-closure-capture proof (CROSSLANG-LINK-FIX01G/H) is a SEPARATE,
        additional gate applied by the caller via `loader_definition_reaches_use()`, not
        by this method; this method's name predates that split and is kept for
        continuity, but what it proves is now precisely SCOPE_UNIQUE, nothing about
        execution order. Returns
        (rhs_arg, def_function_id, assign_call_id, None) for the single, unambiguous,
        correctly-in-scope, unshadowed real definition of `receiver_name` reaching a use
        inside the function identified by `enclosing_function_id` -- `def_function_id`
        and `assign_call_id` (the defining `<operator>.assignment` call's own real CFG
        node id) are what the caller's dominance check needs next. On failure, returns
        (None, None, None, reason) with an explicit, disclosed abstention reason -- never
        a guess. `reason` is one of:
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
            return None, None, None, 'NO_DEFINITION'
        if len(assigns) > 1:
            return None, None, None, 'MULTIPLE_DEFINITIONS_AMBIGUOUS'
        rhs, def_function_id, assign_call_id = assigns[0]
        call_chain = self.function_ancestor_chain(enclosing_function_id)
        def_func = self.functions_by_id.get(def_function_id)
        if not call_chain or def_func is None:
            return None, None, None, 'SCOPE_UNRESOLVED'
        def_full_name = def_func.get('full_name')
        def_index = next((i for i, f in enumerate(call_chain)
                           if f.get('full_name') == def_full_name), None)
        if def_index is None:
            return None, None, None, 'DEFINITION_NOT_IN_SCOPE'
        for f in call_chain[def_index + 1:]:
            for p in f.get('parameters', []):
                if p.get('name') == receiver_name:
                    return None, None, None, 'PARAMETER_SHADOWED'
        return rhs, def_function_id, assign_call_id, None


def _is_const_declaration(assignment_call):
    """CROSSLANG-LINK-FIX01H -- True iff `assignment_call`'s own `code` field (the REAL,
    verbatim source text of this `<operator>.assignment` node, confirmed real via direct
    Joern-REPL query: `const native = require(...)` produces a `code` field that is
    literally `"const native = require(...)"`, keyword included) shows this is a `const`
    DECLARATION-WITH-INITIALIZER, not a bare reassignment (`"native = require(...)"`, no
    leading keyword) and not a `let`/`var` declaration. `let`/`var` are deliberately
    excluded even though `JsCallIndex.receiver_definition`'s own SCOPE_UNIQUE check
    already limits the file to exactly one real `<operator>.assignment` CALL node for
    this name -- that check only sees `<operator>.assignment` nodes; a compound
    assignment, a `for`/`for-in` loop variable, or another real mutation this file's
    index does not model could still alter the SAME `let`/`var` binding without ever
    appearing as a second `<operator>.assignment`. `const` is the one real, frontend-
    confirmed signal that JS's own language semantics forbid rebinding this name at all
    -- required as ONE of several requirements before a cross-function closure capture
    is ever trusted (see `loader_definition_reaches_use`)."""
    code = (assignment_call.get('code') or '').lstrip()
    return code.startswith('const ') or code.startswith('const\t')


def has_closure_binding_evidence(idx, use_function_id, receiver_name):
    """CROSSLANG-LINK-FIX01H -- True iff Joern's OWN real closure-binding evidence
    proves `use_function_id` captures `receiver_name` from an outer scope. Confirmed
    real via direct Joern-REPL query on a dedicated closure fixture (see
    CHARACTERIZATION.md): a nested function that reads an outer `const`/`let`/`var` gets
    its OWN real LOCAL node -- owned by the NESTED function itself, distinct from the
    outer LOCAL -- whose `closureBindingId` is exactly
    `"<capturing-function-full-name>:<captured-variable-name>"`; every real IDENTIFIER
    use of that name INSIDE the nested function `refsTo` THIS inner closure-binding
    LOCAL, not the outer LOCAL directly (also confirmed via REPL). This is Joern's own
    structural proof that the reference really is a closure capture -- a DIFFERENT,
    STRONGER claim than `function_ancestor_chain`'s own lexical-ancestry walk, which
    only proves a same-named declaration exists somewhere in an enclosing scope, not
    that the frontend resolved this specific use as a real capture of it. Do not
    conflate the two: lexical ancestry alone is never treated as cross-function
    dominance or capture evidence anywhere in this file."""
    use_func = idx.functions_by_id.get(use_function_id)
    if use_func is None or not use_func.get('full_name'):
        return False
    key = f"{use_func['full_name']}:{receiver_name}"
    return key in idx.closure_binding_keys


def _declaration_lhs_identifier_id(idx, function_id):
    """CROSSLANG-LINK-FIX01I -- the real id of the IDENTIFIER on the LEFT-hand side of
    `use_function_id`'s own hoisted function-declaration statement (confirmed real via
    Joern-REPL: `function wrapper(){...}` is represented as `<operator>.assignment`
    `"function wrapper = function wrapper() {...}"`, whose argument-index-1 IDENTIFIER
    has the SAME real id as one of the two real IDENTIFIER occurrences of `wrapper`'s
    name found in `identifiers.tsv`). `escape_sites()` excludes this ONE id -- the
    declaration merely makes the (hoisted) name available, it is not itself a use or
    escape of the function VALUE. Returns None if the function's own name or declaring
    assignment cannot be established unambiguously -- callers then conservatively
    include EVERY occurrence as a potential escape site (fails closed: at worst
    over-rejects a safe case, never silently drops a real escape from consideration)."""
    func = idx.functions_by_id.get(function_id)
    if func is None or not func.get('name'):
        return None
    assigns = idx.assignments_by_lhs.get(func['name'])
    if not assigns or len(assigns) != 1:
        return None
    decl_call = idx.calls_by_id.get(assigns[0][2])
    if decl_call is None:
        return None
    lhs = next((a for a in decl_call.get('arguments', []) if a.get('index') == 1), None)
    return lhs.get('id') if lhs else None


def escape_sites(idx, def_function_id, use_function_id):
    """CROSSLANG-LINK-FIX01I -- real ids of every real IDENTIFIER reference to
    `use_function_id`'s own declared name, occurring within `def_function_id`'s own
    scope, that is NOT that function's own declaration LHS. Each one is a real point
    where the closure FUNCTION ITSELF (not merely its return value) is used as a VALUE
    -- passed as an argument (`invoke(wrapper)`), assigned or exported
    (`module.exports.wrapper = wrapper`), returned, stored in a data structure, etc.
    Confirmed real and necessary via direct Joern-REPL query on a dedicated fixture
    (`controls/const_cross_function_escape_probe`, see CHARACTERIZATION.md): passing a
    closure to another function BEFORE the closure's own captured `const` is assigned
    can result in that closure being invoked (via whatever received the reference) at
    ANY later, uncontrolled time -- checking only DIRECT `wrapper()` calls in the
    defining scope (as CROSSLANG-LINK-FIX01H did) misses this entirely; a call like
    `invoke(wrapper)` is not itself a call whose OWN `candidate_target_ids` resolves to
    `use_function_id` (it resolves to `invoke`), so it was invisible to that check.
    Every site returned here must be dominated by the assignment, exactly like a direct
    invocation site, in `loader_definition_reaches_use()`."""
    func = idx.functions_by_id.get(use_function_id)
    if func is None or not func.get('name'):
        return []
    name = func['name']
    exclude_id = _declaration_lhs_identifier_id(idx, use_function_id)
    return [ident['id'] for ident in idx.identifiers_by_method.get(def_function_id, [])
            if ident.get('name') == name and ident['id'] != exclude_id]


def loader_definition_reaches_use(idx, assign_call_id, def_function_id, use_function_id,
                                    use_call_id, receiver_name):
    """CROSSLANG-LINK-FIX01H -- see module docstring for the full, real account of why
    CROSSLANG-LINK-FIX01G's own "dominates its own defining function's exit" check was
    itself an overclaim for the cross-function case: standard CFG dominance is only
    defined WITHIN a single method's own CFG -- a node in a DIFFERENT function's CFG is
    not even part of the same graph, so "the assignment dominates this function's exit"
    proves NOTHING about whether it dominates a node inside some OTHER function's own
    body. FIX01G silently treated that exit-dominance proxy as sufficient for the
    cross-function case too; this was a real, confirmed overclaim, not merely a
    theoretical gap (the common, safe `const native = require(...)(); function
    wrapper(){ return native.Foo(); }` pattern DOES exercise this exact path).

    Returns (evidence_kind, None) on success -- `evidence_kind` is `'dominance_proven'`
    (real, direct, intraprocedural CFG dominance) or `'closure_capture_proven'` (real,
    disclosed closure-capture evidence, a DIFFERENT and NECESSARILY WEAKER kind of proof
    than direct CFG dominance since it can never observe cross-function execution order
    directly) -- or (None, reason) on failure, with an explicit, disclosed reason.
    MISSING OR CROSS-FUNCTION CFG EVIDENCE ALWAYS ABSTAINS: there is no code path here
    that falls back to SCOPE_UNIQUE alone, in either the same-function or cross-function
    branch below.

    SAME-FUNCTION case (`use_function_id == def_function_id`, i.e. assignment and use
    are real nodes in the SAME method's own CFG -- real dominance is meaningful and
    computed DIRECTLY against the specific use node, not a proxy):
      1. `assign_call_id` is CFG-reachable to `use_call_id` and (2) dominates it --
         checked together via `cfg_dominates`, the standard node-removal test; any real
         path that reaches the use without passing through the assignment fails this.
      3. no OTHER definition can reach the use: guaranteed by construction -- SCOPE_
         UNIQUE already established there is exactly one real `<operator>.assignment` to
         this name anywhere in the file, and dominance failing on ANY bypass path (the
         implicit "not yet assigned" state reaching the use on that path) is exactly
         what step 2 rejects.
      4. same CFG/method: true by the branch condition itself.
      -> `CFG_UNAVAILABLE` (use not reachable from entry at all -- cannot establish) or
         `DEFINITION_NOT_DOMINANT` (a real bypass path exists) on failure.

    CROSS-FUNCTION case (`use_function_id != def_function_id`): CFG dominance is NEVER
    attempted here -- it is not a meaningful claim across two different functions' own,
    disconnected CFGs. Real, SEPARATE closure-capture evidence is required instead, ALL
    of:
      a) `_is_const_declaration` -- the assignment is a real `const` declaration
         (language-enforced immutability of the BINDING itself).
      b) `has_closure_binding_evidence` -- Joern's own real, structural proof that
         `use_function_id` captures `receiver_name` from an outer scope (not merely
         lexical-ancestry name lookup).
      c) the assignment dominates its OWN defining function's real exit (`methodReturn`)
         -- proves the module fully finishes loading with the assignment having run,
         which is the real precondition ANY external invocation of a captured closure
         depends on (module-load-then-export is a real language/runtime contract, not a
         CFG fact, which is exactly why this is a DIFFERENT evidence kind, not CFG
         dominance of the use itself).
      d) any real, DIRECT, SAME-DEFINING-SCOPE call whose own `candidate_target_ids`
         names `use_function_id` is ALSO dominated by the assignment -- catches
         assignment-after-use (a synchronous same-scope invocation reached before the
         assignment). Deliberately bounded, disclosed scope, matching this project's own
         established bounded-trace discipline (e.g. `LOADER_ALIAS_DEPTH`): only a DIRECT
         call found within `def_function_id` itself is checked. The common, safe
         "define, then `module.exports`, invoked later by external code after the whole
         module has finished loading" pattern has no such call site to check, so only
         a/b/c apply to it.
      e) CROSSLANG-LINK-FIX01I: every real ESCAPE site (`escape_sites()`) -- any
         reference to the closure FUNCTION ITSELF as a value within `def_function_id`'s
         own scope, not only a direct `wrapper()` call -- is ALSO dominated by the
         assignment. `invoke(wrapper)` passes the function to another call BEFORE
         `wrapper` is ever itself invoked directly; if that escape happens before the
         assignment, `wrapper` could be invoked via whatever received it at ANY later,
         uncontrolled time, with no guarantee the assignment has run yet. Requirement
         (d) alone is blind to this: `invoke(wrapper)`'s own `candidate_target_ids`
         resolves to `invoke`, never to `use_function_id`. Same bounded, disclosed
         same-defining-scope-only discipline as (d).
      -> `DEFINITION_IN_TRY_BLOCK_UNVERIFIABLE`, `CROSS_FUNCTION_NOT_CONST`,
         `CROSS_FUNCTION_NO_CLOSURE_EVIDENCE`, `CROSS_FUNCTION_CFG_UNAVAILABLE`,
         `CROSS_FUNCTION_DEFINITION_NOT_DOMINANT`, `CROSS_FUNCTION_INVOCATION_NOT_DOMINATED`,
         or `CROSS_FUNCTION_ESCAPE_NOT_DOMINATED` on failure.

    Separately (checked by the caller, `resolve_loader_provenance`/
    `_callee_resolves_to_require`, not here): the assignment's own INITIALIZER
    expression must itself be a single, unconditional invocation shape -- a `const`
    declaration only proves the BINDING cannot be reassigned, never which VALUE
    initialized it (CROSSLANG-LINK-FIX01I; see `resolve_loader_provenance`'s own
    docstring for `INITIALIZER_NOT_UNCONDITIONAL`)."""
    if assign_call_id in idx.try_nested_calls:
        return None, 'DEFINITION_IN_TRY_BLOCK_UNVERIFIABLE'

    if use_function_id == def_function_id:
        dom_use = cfg_dominates(idx.cfg_next, def_function_id, assign_call_id, use_call_id)
        if dom_use is None:
            return None, 'CFG_UNAVAILABLE'
        if not dom_use:
            return None, 'DEFINITION_NOT_DOMINANT'
        return 'dominance_proven', None

    # Cross-function: CFG dominance is not a meaningful claim here -- never attempted.
    # Real, separate closure-capture evidence required instead (all four parts, a-d).
    assignment_call = idx.calls_by_id.get(assign_call_id)
    if assignment_call is None or not _is_const_declaration(assignment_call):
        return None, 'CROSS_FUNCTION_NOT_CONST'
    if not has_closure_binding_evidence(idx, use_function_id, receiver_name):
        return None, 'CROSS_FUNCTION_NO_CLOSURE_EVIDENCE'
    exit_id = idx.method_exit.get(def_function_id)
    if exit_id is None:
        return None, 'CROSS_FUNCTION_CFG_UNAVAILABLE'
    dom_exit = cfg_dominates(idx.cfg_next, def_function_id, assign_call_id, exit_id)
    if dom_exit is None:
        return None, 'CROSS_FUNCTION_CFG_UNAVAILABLE'
    if not dom_exit:
        return None, 'CROSS_FUNCTION_DEFINITION_NOT_DOMINANT'
    invocation_sites = [c['id'] for c in idx.calls_by_id.values()
                         if c.get('enclosing_function_id') == def_function_id
                         and use_function_id in (c.get('candidate_target_ids') or [])]
    for site_id in invocation_sites:
        dom_site = cfg_dominates(idx.cfg_next, def_function_id, assign_call_id, site_id)
        if not dom_site:  # False (proven not dominant) and None (unreachable) both reject
            return None, 'CROSS_FUNCTION_INVOCATION_NOT_DOMINATED'
    # CROSSLANG-LINK-FIX01I, requirement (e): every real escape of the closure function
    # itself -- passed as a value, assigned, exported, returned -- not only a direct
    # `wrapper()` call, must also be dominated by the assignment.
    for site_id in escape_sites(idx, def_function_id, use_function_id):
        dom_site = cfg_dominates(idx.cfg_next, def_function_id, assign_call_id, site_id)
        if not dom_site:
            return None, 'CROSS_FUNCTION_ESCAPE_NOT_DOMINATED'
    return 'closure_capture_proven', None


def _is_unconditional_invocation_shape(call):
    """CROSSLANG-LINK-FIX01I -- True iff `call`'s own `name` field shows it is a real,
    single, unconditional INVOCATION (`require(pkg)(...)`, a plain alias `f(...)`, or a
    bare `require(pkg)`) rather than some OTHER operator construct (a ternary
    `cond ? a : b`, `a || b`, `a && b`, `a ?? b`, etc.) whose real runtime value could be
    EITHER branch. Confirmed real and necessary via direct Joern-REPL query: a real
    invocation's own `name` field is always the callee's own source text (e.g.
    `"require('node-gyp-build')"`, or a plain identifier like `"loaderFn"`), while every
    JS operator construct is represented with a `name` that starts with the literal
    `"<operator>."` prefix (confirmed: a ternary's own `name` is exactly
    `"<operator>.conditional"`) -- a real, structural, non-overlapping distinction, not
    a guess. A `const` declaration only proves the BINDING cannot be reassigned; it says
    NOTHING about which of several possible branches actually initialized it, so this
    check runs BEFORE `_callee_resolves_to_require` is ever tried, and rejects with
    `'INITIALIZER_NOT_UNCONDITIONAL'` before `'CALLEE_NOT_REQUIRE'` could ever be
    reached -- critically, this means the marker-regex fallback (gated behind
    `'CALLEE_NOT_REQUIRE'` specifically) is NEVER reached for this shape either. This
    matters in practice, not just in theory: confirmed via REPL that jssrc2cpg's own
    type-recovery pass can silently resolve a ternary's `receiver_type` to the LOADER
    branch's type alone, discarding the other branch entirely (`flag ? require(pkg)
    (...) : fake` produced `typeFullName == "node-gyp-build"` for every use of the
    receiver) -- WITHOUT this check, the regex fallback could have matched on exactly
    that silently-collapsed type, right through this design's own dominance/closure
    gates, which check WHERE the assignment reaches, never WHAT value it evaluates to."""
    name = call.get('name') or ''
    return not name.startswith('<operator>.')


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
    # unresolved scope, or shadowing; see receiver_definition's own docstring), then
    # (CROSSLANG-LINK-FIX01H) require the SAME real dominance-or-closure-capture proof
    # this alias hop's own definition reaches THIS invocation -- an alias is exactly as
    # capable of being defined in a dead branch, after this invocation, or captured
    # cross-function without real closure evidence, as the top-level receiver is.
    next_rhs, next_def_fn, next_assign_id, reason = idx.receiver_definition(
        callee_name, invocation_call.get('enclosing_function_id'))
    if next_rhs is None or next_rhs.get('kind') != 'CALL':
        return None
    evidence_kind, _reason = loader_definition_reaches_use(
        idx, next_assign_id, next_def_fn, invocation_call.get('enclosing_function_id'),
        invocation_call['id'], callee_name)
    if evidence_kind is None:
        return None
    next_rhs_call = idx.calls_by_id.get(next_rhs['id'])
    if next_rhs_call is None:
        return None
    # CROSSLANG-LINK-FIX01I: the alias's own initializer must ALSO be a single,
    # unconditional invocation shape -- see `_is_unconditional_invocation_shape`'s own
    # docstring. An alias behind a ternary/logical-short-circuit is exactly as unsound
    # as the top-level receiver being behind one.
    if not _is_unconditional_invocation_shape(next_rhs_call):
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


def resolve_loader_provenance(receiver_name, enclosing_function_id, use_call_id, idx,
                                curated_packages, depth=LOADER_ALIAS_DEPTH):
    """Real evidence (see module docstring) that `receiver_name`'s value, AS SEEN FROM
    WITHIN `enclosing_function_id`'s own scope AT THE REAL USE NODE `use_call_id`,
    originates from INVOKING one of `curated_packages` -- gated by BOTH SCOPE_UNIQUE
    reaching-definition evidence (`JsCallIndex.receiver_definition`) AND real
    dominance-or-closure-capture proof (CROSSLANG-LINK-FIX01H,
    `loader_definition_reaches_use`) that the definition reaches the use with respect to
    execution order, not merely lexical scope. Returns (pkg, evidence_kind) on full
    proof -- `evidence_kind` is `'dominance_proven'` or `'closure_capture_proven'`,
    whichever `loader_definition_reaches_use` established -- else (None, reason) --
    `reason` is one of `JsCallIndex.receiver_definition`'s own disclosed abstention
    codes, `loader_definition_reaches_use`'s own disclosed abstention codes, or
    `'NOT_AN_INVOCATION'`/`'BARE_LOADER_REFERENCE'`/`'CALLEE_NOT_REQUIRE'` for a real,
    in-scope, unambiguous, reachability-proven definition whose value simply isn't a
    loader invocation. Caller falls back to the explicitly-labeled, lower-confidence
    marker-regex heuristic ONLY on `'CALLEE_NOT_REQUIRE'` -- which, by construction, is
    reached ONLY after the dominance-or-closure-capture gate below has already passed,
    so the fallback tier is automatically subject to the identical gate with no
    separate plumbing."""
    rhs, def_function_id, assign_call_id, reason = idx.receiver_definition(
        receiver_name, enclosing_function_id)
    if rhs is None:
        return None, reason
    evidence_kind, reach_reason = loader_definition_reaches_use(
        idx, assign_call_id, def_function_id, enclosing_function_id, use_call_id,
        receiver_name)
    if evidence_kind is None:
        return None, reach_reason
    if rhs.get('kind') != 'CALL':
        return None, 'NOT_AN_INVOCATION'
    rhs_call = idx.calls_by_id.get(rhs['id'])
    if rhs_call is None:
        return None, 'NOT_AN_INVOCATION'
    # CROSSLANG-LINK-FIX01I: `const` proves the BINDING cannot be reassigned; it proves
    # NOTHING about which value initialized it. Reject BEFORE `_callee_resolves_to_
    # require` (and therefore before `'CALLEE_NOT_REQUIRE'` -- the only reason the
    # marker-regex fallback is ever tried -- can be reached) if the initializer is not a
    # single, unconditional invocation shape. See `_is_unconditional_invocation_shape`'s
    # own docstring for why this is a REAL, not merely theoretical, risk.
    if not _is_unconditional_invocation_shape(rhs_call):
        return None, 'INITIALIZER_NOT_UNCONDITIONAL'
    # receiver_name = rhs_call(...) -- receiver is the INVOCATION of rhs_call's own
    # callee. A BARE `receiver = require(pkg)` (rhs_call itself IS the require call, no
    # separate invocation wrapping it) is the loader-helper-itself case -- correctly NOT
    # a match here (confirmed real: this is exactly `const loader = require('node-gyp-
    # build'); loader.path(x)`'s own shape).
    if rhs_call.get('name') == 'require':
        return None, 'BARE_LOADER_REFERENCE'
    pkg = _callee_resolves_to_require(rhs_call, idx, curated_packages, depth)
    return (pkg, evidence_kind) if pkg else (None, 'CALLEE_NOT_REQUIRE')


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
    own receiver is a native-binding object. `tier` is `"dominance_proven"` (real,
    direct, intraprocedural CFG dominance -- assignment and use are real nodes in the
    SAME function's own CFG) or `"closure_capture_proven"` (real, disclosed,
    NECESSARILY WEAKER cross-function evidence -- see `loader_definition_reaches_use`'s
    own docstring for exactly what each requires; named `"dominance_proven"`/
    `"closure_capture_proven"` rather than the earlier `"canonical"` because
    CROSSLANG-LINK-FIX01G/H found scope-uniqueness alone does NOT establish provenance,
    and cross-function CFG "dominance" was itself an overclaim -- see module docstring),
    `"fallback_marker_regex"` (tried ONLY when the resolver established a real, safe,
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
        pkg, reason_or_tier = resolve_loader_provenance(
            receiver_name, call.get('enclosing_function_id'), call['id'], idx,
            NATIVE_LOADER_PACKAGES)
        if pkg:
            return True, reason_or_tier, None
        reason = reason_or_tier
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
        # CROSSLANG-LINK-FIX01G/H: real, disclosed dominance/closure-capture abstentions
        # -- see `loader_definition_reaches_use()`'s own docstring for what each means.
        'DEFINITION_NOT_DOMINANT', 'CFG_UNAVAILABLE',
        'DEFINITION_IN_TRY_BLOCK_UNVERIFIABLE',
        'CROSS_FUNCTION_NOT_CONST', 'CROSS_FUNCTION_NO_CLOSURE_EVIDENCE',
        'CROSS_FUNCTION_CFG_UNAVAILABLE', 'CROSS_FUNCTION_DEFINITION_NOT_DOMINANT',
        'CROSS_FUNCTION_INVOCATION_NOT_DOMINATED',
        # CROSSLANG-LINK-FIX01I: real, disclosed abstentions -- see
        # `_is_unconditional_invocation_shape`/`escape_sites`'s own docstrings.
        'INITIALIZER_NOT_UNCONDITIONAL', 'CROSS_FUNCTION_ESCAPE_NOT_DOMINATED',
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
    n_dominance = sum(1 for l in linked if l['evidence_tier'] == 'dominance_proven')
    n_closure = sum(1 for l in linked if l['evidence_tier'] == 'closure_capture_proven')
    n_fallback = sum(1 for l in linked if l['evidence_tier'] == 'fallback_marker_regex')
    print(f"POLYGLOT registrations={len(table)} linked_js_calls={len(linked)} "
          f"(dominance_proven={n_dominance} closure_capture_proven={n_closure} "
          f"fallback_regex={n_fallback} "
          f"other={len(linked) - n_dominance - n_closure - n_fallback}) "
          f"unlinked={len(unlinked)} abstained={len(abstained)}")

if __name__ == '__main__':
    main()
