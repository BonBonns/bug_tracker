#!/usr/bin/env python3
"""Call-context guard propagation -- a shared fact-derivation module (not a verdict
producer itself) consumed by oob_runtime_capacity_verdict.py. Establishes
CallContextGuardFact records, ONE PER (call site, protected-expression-pair), never
merged across call sites:

    CallContextGuardFact
      call_site_identity     -- the call's own id (a specific textual call site,
                                 not "this callee in general")
      caller_identity        -- enclosing function id of the call site
      callee_identity        -- the statically-resolved target function id
      actual_to_formal_mapping -- {callee_param_name: caller_argument_expr}, built
                                 STRICTLY by argument INDEX matched to parameter
                                 INDEX (never by name or position-guessing -- "
                                 arguments passed in a different order" must still
                                 resolve correctly)
      normalized_predicate   -- the caller-side comparison's code text, if any
                                 qualifying candidate was found
      enforcement_kind       -- 'RUNTIME_BRANCH' | 'ASSERTION_ONLY' | 'NONE'
      dominates_call         -- True | False | None (None = no CFG data to decide)
      controls_call          -- True | False | None -- REQUIRED IN ADDITION TO
                                 dominates_call, not implied by it. A comparison
                                 can dominate a call (execute on every path to it)
                                 while having NO bearing on whether the call
                                 actually happens: `if (x) { log_error(); }
                                 target();` -- the comparison dominates `target()`
                                 but BOTH of its outcomes still reach it, so
                                 crediting it as protection would be wrong.
                                 `controls_call` is True only when at least one of
                                 the comparison's own CFG successor edges does NOT
                                 reach the call at all -- a genuinely rejecting
                                 branch (`if (x) { return ERR; }`) or a genuinely
                                 gating one (the call lives only inside the "safe"
                                 branch). None when there's no CFG data to decide.
      type_and_range_evidence -- descriptive list of resolved types for the two
                                 compared expressions -- ALWAYS recorded when
                                 resolvable, never silently dropped, even though it
                                 does not by itself prove or disprove safety
      establishment_status   -- 'CREDITED' | 'NOT_CREDITED' | 'AMBIGUOUS' | 'UNRESOLVED'

WHY THIS EXISTS: round 12 showed NSS CVE-2019-17006's actual fix is a caller-side
guard (`rsa_FormatBlock`'s `PORT_Assert(...)` replaced by a real `if` check) that
protects a write inside a DIFFERENT function (`rsa_FormatOneBlock`) -- one call
frame away from where the capacity/write live. This module answers, for one
specific call site, whether a caller-side guard PROVABLY protects a given pair of
expressions (typically a write's width and its capacity, expressed in the callee,
then mapped back into the caller's own argument expressions).

FOR A GUARD TO BE CREDITED, ALL of the following must hold (checked in order):
  1. The comparison is an ENFORCED runtime branch, not merely inside an
     assert-family macro (MOZ_ASSERT/PORT_Assert/... -- compiled out in release,
     never counts as protection, matches this whole producer family's existing
     assert-exclusion posture).
  2. The guard DOMINATES the call site -- every path from the caller's entry to
     this specific call passes through the guard. Determined via this repo's own
     `cfg_edges` facts (dominator sets, same machinery as round 12's free
     invalidation), NEVER via source line order.
  3. The guard also CONTROLS the call -- dominance alone is NOT sufficient. A
     real bug found testing against the actual CVE-2019-17006 patched revision
     (caught by review before being trusted, not by a synthetic fixture -- none
     of round 13's original 7 exercised this shape): `if (x > y) { log(); }
     target();` has its comparison DOMINATE `target()` (nothing bypasses it
     structurally), yet BOTH of the comparison's own outcomes still reach
     `target()` -- the branch changes nothing about whether the call executes,
     so it must NOT be credited, even though the earlier, dominance-only version
     of this module would have. `controls_call` requires that at least one of
     the comparison's own CFG successor edges does NOT reach the call at all --
     a genuinely rejecting branch (`if (x) { return ERR; } target();`) or the
     call living only inside the "safe" branch (`if (x_is_safe) { target(); }`).
     Checked via plain CFG reachability from each successor edge, not by trying
     to label which edge is "true" vs "false" (the reachability test alone
     already produces the correct answer regardless of the predicate's polarity).
  4. The guarded caller expressions map to the ACTUAL arguments passed at THIS
     call site, matched by argument index to callee parameter index.
  5. (checked by the CONSUMER, not this module) the callee parameter reaches the
     write/size calculation this guard is meant to protect.
  6. type_and_range_evidence is recorded for both compared expressions; if their
     resolved types have DIFFERENT signedness, this module cannot rule out that a
     C usual-arithmetic-conversion changes the predicate's real meaning (a signed
     value compared against an unsigned one is converted to unsigned first, which
     can turn a negative value into a huge one) -- establishment_status becomes
     UNRESOLVED rather than CREDITED, "unresolved without range proof" this module
     does not attempt to construct.
  7. Every fact is tied to ITS OWN call site -- multiple call sites into the same
     callee are never merged into one function-wide conclusion. A consumer must
     query every call site reaching a callee and require ALL of them CREDITED
     before treating a callee-local write as protected; if even one call site is
     unguarded, the candidate remains live for that reason alone.

Classification for guard-vs-call ordering, reusing the same dominance +
reachability primitives as round 12's free invalidation (guard "protects" a call
exactly the way an allocation "reaches" a sink there), PLUS the control-dependence
check above:
  - guard DOMINATES call AND CONTROLS it (a genuine rejecting/gating branch
    exists)                                                -> real check: CREDITED
                                                                 assert only: NOT_CREDITED
  - guard DOMINATES call but does NOT control it (every branch reaches the call
    regardless)                                             -> NOT_CREDITED (fail
    closed -- dominance without control-dependence is never protection)
  - guard does NOT dominate, but call IS reachable from guard -> AMBIGUOUS (only on
    one incoming branch -- the guard sometimes executes before the call, sometimes
    not, e.g. a conditional check that rejoins before the call)
  - guard does NOT dominate, and call is NOT reachable from guard -> NOT_CREDITED
    (the guard occurs after the call, or on an unrelated branch that never reaches
    it -- irrelevant either way)
"""
import re
from allocation_extent import build_cfg_index, _reachable_from, _dominates

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')
NAME_CHAIN = r'[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*'
UNSIGNED_HINT_RE = re.compile(r'\bunsigned\b|\bUINT|\bPRUint|\bCK_ULONG|\bsize_t\b', re.I)


def _collect_assert_codes(d):
    calls = d.get('calls', [])
    return [(c.get('code') or '') for c in calls
            if c.get('name') in ASSERT_NAMES
            or (c.get('code', '').split('(')[0].strip() in ASSERT_NAMES)]


def _collect_assert_arg_ids(d):
    """Node ids of every expression PASSED AS AN ARGUMENT to an assert-family call --
    identity-based, not text-based. Found as a real bug: NSS's `PORT_Assert(x)` macro
    (Joern name `PR_ASSERT`) renders its OWN `code` with inner macros expanded (e.g.
    `RSA_BLOCK_MIN_PAD_LEN` folded to `8`), but the SAME comparison extracted as its
    own `<operator>...` node keeps the unexpanded macro name in ITS `code`
    (`data->len <= (modulusLen - (3 + RSA_BLOCK_MIN_PAD_LEN))` vs
    `PR_ASSERT(data->len <= (modulusLen - (3 + 8)))`). A pure substring check
    (`cc in ac`) then wrongly concludes the comparison is NOT inside the assert --
    silently crediting an assertion-only guard as real enforcement. The two AST
    nodes share the same `id` (confirmed on real NSS rsapkcs.c: the assert's
    `arguments[0].id` IS the comparison's own `id`), so identity is the sound way to
    decide this, with the old text check kept only as a fallback for shapes without
    id linkage."""
    ids = set()
    for c in d.get('calls', []):
        if c.get('name') not in ASSERT_NAMES and (c.get('code', '').split('(')[0].strip() not in ASSERT_NAMES):
            continue
        for a in c.get('arguments', []):
            if a.get('id') is not None:
                ids.add(a.get('id'))
            vr = a.get('value_ref') or {}
            if vr.get('id') is not None:
                ids.add(vr.get('id'))
    return ids


def _in_assert(call, assert_codes, assert_ids=None):
    """`call` is the CANDIDATE comparison's own call dict (not just its code) so
    identity-based matching (see `_collect_assert_arg_ids`) can be tried first."""
    if assert_ids and call.get('id') in assert_ids:
        return True
    cc = (call.get('code') or '').strip()
    return bool(cc) and any(cc in ac for ac in assert_codes)


def _resolve_expr_type(d, fn, expr):
    """Best-effort type resolution for a bare identifier or a ONE-HOP field-access
    expression (`name` or `name->field` / `name.field`), used only to populate
    type_and_range_evidence and the signedness check -- never a general type
    system. Returns a type string or None."""
    m = re.fullmatch(r'([A-Za-z_]\w*)(?:(?:->|\.)([A-Za-z_]\w*))?', expr or '')
    if not m:
        return None
    base, field = m.group(1), m.group(2)
    base_type = None
    for l in d.get('locals', []):
        if l.get('method_id') == fn and l.get('name') == base:
            base_type = l.get('type_full_name')
            break
    if base_type is None:
        for f in d.get('functions', []):
            if f.get('id') != fn:
                continue
            for p in f.get('parameters', []):
                if p.get('name') == base:
                    base_type = p.get('type_full_name')
                    break
    if field is None or base_type is None:
        return base_type
    type_name = base_type.rstrip('*').strip()
    type_decl_id = None
    for t in d.get('type_decls', []):
        if t.get('name') == type_name:
            type_decl_id = t.get('id')
            break
    if type_decl_id is None:
        return None
    for m2 in d.get('members', []):
        if m2.get('type_decl_id') == type_decl_id and m2.get('name') == field:
            return m2.get('type_full_name')
    return None


def _signedness(type_str):
    if not type_str:
        return None
    return 'unsigned' if UNSIGNED_HINT_RE.search(type_str) else 'signed'


NEG_OP = {
    '<operator>.lessThan': '<operator>.greaterEqualsThan',
    '<operator>.lessEqualsThan': '<operator>.greaterThan',
    '<operator>.greaterThan': '<operator>.lessEqualsThan',
    '<operator>.greaterEqualsThan': '<operator>.lessThan',
}
OP_SYMBOL = {
    '<operator>.lessThan': '<', '<operator>.lessEqualsThan': '<=',
    '<operator>.greaterThan': '>', '<operator>.greaterEqualsThan': '>=',
}


def _is_terminal_chain(g, start):
    """True iff `start` and every node reachable from it forms a SIMPLE,
    non-branching chain that ends in a genuine dead end (a node with zero
    outgoing edges) -- the CFG shape of `{ cleanup(); ...; return ERR; }`, no
    matter how many straight-line statements precede the return. False for a
    cycle, or for ANY node along the way that branches again (2+ successors) --
    deliberately conservative: a reject arm complex enough to branch further is
    NOT confidently classified as "this path never continues normal execution",
    so callers must not guess and must fall back to NOT establishing polarity."""
    seen = set()
    n = start
    limit = len(g['nodes']) + 5
    steps = 0
    while True:
        if n in seen:
            return False
        seen.add(n)
        succs = g['succ'].get(n) or set()
        if not succs:
            return True
        if len(succs) != 1:
            return False
        n = next(iter(succs))
        steps += 1
        if steps > limit:
            return False


def _branch_polarity(g, cmp_node, call_id):
    """Determines whether reaching `call_id` PROVES the NEGATION of `cmp_node`'s
    own predicate held, using only CFG structure -- never source line order or
    edge ordering (this repo's `cfg_edges` carry no true/false label at all).

    Returns 'NEGATED' when this is soundly provable: `cmp_node` has exactly 2
    successors, exactly one of them reaches the call (`_controls_call`'s
    condition), and the OTHER (non-reaching) successor is a genuine terminal
    chain (`_is_terminal_chain`) -- the `if (P) { return ERR; } target();` shape.
    By C `if` semantics, a body consisting SOLELY of straight-line code ending in
    a hard return is entered exactly when P is true and NOTHING ELSE reaches
    that arm -- so reaching the call at all proves P did NOT hold, i.e. the
    NEGATION of the predicate as literally written.

    Returns None when polarity cannot be soundly established this way (fewer/more
    than 2 successors, ambiguous reaching set, or the non-reaching arm does NOT
    dead-end -- e.g. `if (P) { target(); }` with the call nested inside the
    consequent instead: the reject arm there just continues normal execution
    elsewhere, so this method can't distinguish which side is "true" without
    guessing, and a real bug -- crediting a guard whose predicate's stated
    direction was actually the OPPOSITE of what protects the call, e.g.
    `if (length <= capacity) { return; } target(length);`, where the call is
    only reached when length > capacity -- proves dominance/control-dependence
    ALONE is not enough; only a PROVEN negation, never an assumed one, may be
    credited). Callers must NOT_CREDIT rather than guess when this returns None."""
    succs = list(g['succ'].get(cmp_node) or ())
    if len(succs) != 2:
        return None
    reach = {s: _reachable_from(g['succ'], s) for s in succs}
    reaching = [s for s in succs if call_id in reach[s]]
    nonreaching = [s for s in succs if call_id not in reach[s]]
    if len(reaching) != 1 or len(nonreaching) != 1:
        return None
    if not _is_terminal_chain(g, nonreaching[0]):
        return None
    return 'NEGATED'


def _split_predicate(code, op_name):
    """Splits a comparison's own `code` at its operator into (lhs, rhs) text,
    using the OPERATOR ALREADY KNOWN from `op_name` (never guessed from text) to
    pick the exact symbol -- avoids the `<` vs `<=` substring-ambiguity trap.
    Returns None if the expected symbol isn't found (unexpected code shape)."""
    sym = OP_SYMBOL.get(op_name)
    if not sym or sym not in (code or ''):
        return None
    idx = code.index(sym)
    return code[:idx].strip(), code[idx + len(sym):].strip()


def _entails_safe_bare(op_name, lhs, rhs, expr_width, expr_cap):
    """Sound ONLY for an EXACT two-BARE-operand comparison (`lhs`/`rhs`, after
    whitespace stripping, equal EXACTLY `expr_width` or `expr_cap` -- no
    compound arithmetic on either side). Returns True (the relation `lhs op_name
    rhs` PROVES `width <= cap`), False (it does not), or None when the shape
    isn't a bare two-operand match at all -- e.g. a real guard found on NSS
    rsapkcs.c compares width against `(cap - SOME_MACRO)`, a compound RHS. This
    is DELIBERATELY not extended to reason about such adjustments: proving
    `cap - X <= cap` requires proving `X >= 0`, which is exactly the same class
    of unproven-arithmetic assumption round 12's additive-term soundness fix
    already rejected for capacity expressions ("checking only for subtraction
    does not establish addition safety... without that evidence the verdict
    should remain unresolved") -- the same discipline applies here: an
    un-provable adjustment must fall through to NOT_CREDITED, never be assumed
    safe by the adjustment's name or apparent intent."""
    if lhs == expr_width and rhs == expr_cap:
        return op_name in ('<operator>.lessThan', '<operator>.lessEqualsThan')
    if lhs == expr_cap and rhs == expr_width:
        return op_name in ('<operator>.greaterThan', '<operator>.greaterEqualsThan')
    return None


def _controls_call(g, cmp_node, call_id):
    """True iff `cmp_node` genuinely CONTROLS whether `call_id` executes -- at
    least one of its own CFG successor edges does NOT reach the call at all.
    Dominance is necessary but NOT sufficient for this: `if (x) { log(); }
    target();` has its comparison dominate `target()` (nothing bypasses it),
    but BOTH successors of the comparison still reach `target()`, so the branch
    outcome has no bearing on whether it executes. A genuinely rejecting branch
    (`if (x) { return ERR; } target();`) or a genuinely gating one (the call
    lives only inside the branch taken when the condition is "safe") instead has
    at least one successor edge from which the call is unreachable -- that is
    what this checks, via plain forward reachability per successor edge (no
    attempt to label which edge is "true" vs "false"; the reachability test
    alone gives the right answer regardless of the predicate's polarity).
    A comparison with fewer than 2 successors isn't a real branch point at all
    (nothing to control anything with) and returns False."""
    succs = g['succ'].get(cmp_node) or set()
    if len(succs) < 2:
        return False
    for s in succs:
        if call_id not in _reachable_from(g['succ'], s):
            return True
    return False


def build_actual_to_formal_mapping(d, call, callee_fn):
    """{callee_param_name: caller_argument_expr}, matched strictly by index."""
    params = {}
    for f in d.get('functions', []):
        if f.get('id') == callee_fn:
            for p in f.get('parameters', []):
                params[p.get('index')] = p.get('name')
            break
    mapping = {}
    for a in call.get('arguments', []):
        idx = a.get('index')
        pname = params.get(idx)
        if pname is not None:
            mapping[pname] = (a.get('code') or '').strip()
    return mapping


def guard_status_for_call(d, cfg_index, call, expr_width, expr_cap, assert_codes=None, assert_ids=None):
    """CallContextGuardFact for ONE call site, answering whether a qualifying
    caller-side guard protects the relationship between `expr_width` and
    `expr_cap` (already mapped into CALLER-space by the consumer via
    `build_actual_to_formal_mapping`)."""
    caller_fn = call.get('enclosing_function_id')
    call_id = call.get('id')
    fact = {
        'call_site_identity': call_id, 'caller_identity': caller_fn,
        'callee_identity': (call.get('candidate_target_ids') or [None])[0],
        'normalized_predicate': None, 'enforcement_kind': 'NONE',
        'dominates_call': None, 'controls_call': None,
        'type_and_range_evidence': [], 'establishment_status': 'UNRESOLVED',
    }
    w_type = _resolve_expr_type(d, caller_fn, expr_width)
    c_type = _resolve_expr_type(d, caller_fn, expr_cap)
    if w_type:
        fact['type_and_range_evidence'].append(f"{expr_width}: caller-side type={w_type}")
    if c_type:
        fact['type_and_range_evidence'].append(f"{expr_cap}: caller-side type={c_type}")
    w_sign, c_sign = _signedness(w_type), _signedness(c_type)
    signedness_mismatch = w_sign is not None and c_sign is not None and w_sign != c_sign
    if signedness_mismatch:
        fact['type_and_range_evidence'].append(
            f"SIGNEDNESS MISMATCH between {expr_width} ({w_sign}) and {expr_cap} ({c_sign}) -- "
            "a C usual-arithmetic-conversion could change this predicate's real meaning; "
            "no range proof available")

    if assert_codes is None:
        assert_codes = _collect_assert_codes(d)
    if assert_ids is None:
        assert_ids = _collect_assert_arg_ids(d)
    g = cfg_index.get(caller_fn)

    candidates = []
    for c in d.get('calls', []):
        if c.get('enclosing_function_id') != caller_fn or c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        toks = set(re.findall(NAME_CHAIN, code))
        if expr_width not in toks or expr_cap not in toks:
            continue
        is_assert = _in_assert(c, assert_codes, assert_ids)
        dominates = None
        controls = None
        if g and call_id in g['nodes'] and c.get('id') in g['nodes']:
            dominates = _dominates(g, c.get('id'), call_id)
            if dominates:
                controls = _controls_call(g, c.get('id'), call_id)
        candidates.append((c, is_assert, dominates, controls))

    if not candidates:
        return fact   # UNRESOLVED -- no comparison in the caller mentions both

    # prefer: dominates+controls (genuine protection) > dominates-only (reported,
    # but can never become CREDITED -- see _controls_call) > reachable/ambiguous > other
    best = None
    for c, is_assert, dominates, controls in candidates:
        if dominates is True and controls is True:
            best = (c, is_assert, dominates, controls)
            break
    if best is None:
        for c, is_assert, dominates, controls in candidates:
            if dominates is True:
                best = (c, is_assert, dominates, controls)
                break
    if best is None:
        for c, is_assert, dominates, controls in candidates:
            if dominates is False and g:
                reach = _reachable_from(g['succ'], c.get('id'))
                if call_id in reach:
                    best = (c, is_assert, 'ambiguous', None)
                    break
    if best is None:
        best = candidates[0]

    c, is_assert, dom_state, controls = best
    fact['normalized_predicate'] = c.get('code')
    if dom_state is True:
        fact['dominates_call'] = True
        fact['controls_call'] = controls
        if is_assert:
            fact['enforcement_kind'] = 'ASSERTION_ONLY'
            fact['establishment_status'] = 'NOT_CREDITED'
        elif not controls:
            fact['enforcement_kind'] = 'RUNTIME_BRANCH'
            fact['establishment_status'] = 'NOT_CREDITED'   # dominates but does not
            fact['type_and_range_evidence'].append(          # control the call -- see
                "DOMINATES the call but does NOT CONTROL it -- every outgoing "  # _controls_call
                "branch of this comparison still reaches the call, so its "
                "outcome has no bearing on whether the call executes; fail "
                "closed, dominance alone is never protection")
        else:
            fact['enforcement_kind'] = 'RUNTIME_BRANCH'
            # controls_call proves SOME branch determines whether the call
            # executes -- it does NOT by itself prove the REACHING branch is the
            # SAFE one. `if (length <= capacity) { return; } target(length);`
            # controls the call exactly as much as the real, correct guard does,
            # yet the call is reached precisely when length > capacity (unsafe).
            # Branch polarity must be established from CFG structure, never
            # assumed from the predicate's surface wording.
            polarity = _branch_polarity(g, c.get('id'), call_id)
            if polarity != 'NEGATED':
                fact['establishment_status'] = 'NOT_CREDITED'
                fact['type_and_range_evidence'].append(
                    "CONTROLS the call but branch POLARITY could not be proven "
                    "from CFG structure (the non-reaching arm is not a clean, "
                    "provably-terminal reject chain) -- which branch is 'safe' "
                    "is unknown, so this guard is not credited rather than "
                    "guessed at")
            else:
                split = _split_predicate(c.get('code'), c.get('name'))
                entails = (_entails_safe_bare(NEG_OP[c.get('name')], split[0], split[1],
                                               expr_width, expr_cap) if split else None)
                if entails is not True:
                    fact['establishment_status'] = 'NOT_CREDITED'
                    fact['type_and_range_evidence'].append(
                        "reaching the call proves the NEGATION of "
                        f"'{c.get('code')}', but that negated relation does not "
                        "PROVABLY entail width<=capacity -- either the predicate "
                        "isn't a bare two-operand comparison of exactly these two "
                        "expressions (e.g. one side has an unproven arithmetic "
                        "adjustment, same unproven-arithmetic concern round 12's "
                        "additive-term fix already rejected), or its direction is "
                        "simply the wrong way around; not credited either way")
                elif signedness_mismatch:
                    fact['establishment_status'] = 'UNRESOLVED'
                else:
                    fact['establishment_status'] = 'CREDITED'
    elif dom_state == 'ambiguous':
        fact['dominates_call'] = False
        fact['enforcement_kind'] = 'ASSERTION_ONLY' if is_assert else 'RUNTIME_BRANCH'
        fact['establishment_status'] = 'AMBIGUOUS'
    else:
        fact['dominates_call'] = False
        fact['enforcement_kind'] = 'ASSERTION_ONLY' if is_assert else 'RUNTIME_BRANCH'
        fact['establishment_status'] = 'NOT_CREDITED'   # occurs after call / unrelated branch
    return fact


def find_call_sites(d, callee_fn):
    """Every statically-EXACT-resolved call site targeting `callee_fn`, anywhere in
    the file -- the set a consumer must check ALL of before crediting a
    function-wide suppression (never merge into one conclusion)."""
    return [c for c in d.get('calls', [])
            if c.get('resolution') == 'EXACT' and (c.get('candidate_target_ids') or []) == [callee_fn]]
