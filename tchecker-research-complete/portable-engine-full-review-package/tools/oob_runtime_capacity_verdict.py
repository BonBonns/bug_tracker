#!/usr/bin/env python3
"""OOB_WRITE (RUNTIME_CAPACITY) candidate producer -- consumes allocation_extent.py's
AllocationExtentFact propagation to recognize unguarded call-argument writes into
DYNAMICALLY-ALLOCATED buffers (malloc/PORT_Alloc/calloc/... via allocator_contracts.py),
including SYMBOLIC extents (e.g. `capacity(block) = modulusLen`, a parameter name,
not a folded literal) -- something no prior producer in this family attempts, since
they all require a compile-time-sized local array or a LITERAL-folding heap
allocation.

Reuses the SAME contract-driven BufferOperationFact sink extraction as
oob_call_sink_verdict.py (callee_contracts.py) -- this module's only new
contribution is a NEW capacity SOURCE (a propagated AllocationExtentFact), never a
change to how a candidate is judged once a capacity is known.

GUARD CREDITING for symbolic capacities: a `sizeof(name)` guard (the mechanism the
rest of this family uses) is meaningless for a raw pointer -- `sizeof(ptr)` is the
POINTER'S size, not the pointee's, the classic C footgun. Instead, this module
credits a non-assert comparison that relates the write's width expression DIRECTLY
to the capacity's own size_expression (e.g. `if (dataLen > modulusLen)`) -- the
runtime-capacity analog of the same "does a real (non-assert) check exist relating
the write bound to the destination's actual capacity" question every producer in
this family asks, just keyed on a symbolic expression instead of `sizeof(arr)`.

FREE HANDLING is CFG-SENSITIVE and PER-SINK (`allocation_extent.capacity_status_at_sink`),
not whole-function: a free only disqualifies a capacity at a specific write when
that free is proven, by dominance over this repo's own `cfg_edges` facts, to
execute on EVERY path between the allocation and that write. A free confined to an
error branch that returns before reaching the write does not disqualify it; a
conditional free that rejoins before the write yields AMBIGUOUS (not confidently
usable, but not confidently invalid either) rather than silently abstaining on the
whole function the way an earlier version of this module did.

CALLER-CONTEXT GUARD SUPPRESSION (round 13): when a write's own function has no
local guard, this module now ALSO checks whether EVERY statically-resolved call
site reaching that function has a caller-side guard (real, call-dominating,
type-consistent -- see call_context_guard.py) protecting the SAME
width-vs-capacity relationship, mapped from the callee's expressions back into
each caller's own argument expressions by argument INDEX (never by name-guessing
or position order). Suppression requires ALL reaching call sites to be CREDITED;
if even one is not (unguarded, assert-only, ambiguous, or the relationship can't
be mapped/resolved), the candidate remains -- per-call-site evidence is never
collapsed into one function-wide verdict.

Never emits VULNERABLE; only CANDIDATE. If in doubt, SUPPRESS or ABSTAIN.
"""
import json, re, sys
from callee_contracts import CALLEE_CONTRACTS
from allocation_extent import compute_allocation_extents, compute_free_sites, build_cfg_index, capacity_status_at_sink
from call_context_guard import (build_actual_to_formal_mapping, guard_status_for_call,
                                 find_call_sites, _collect_assert_arg_ids)


def _map_expr_to_caller_space(expr, callee_fn, call_sites, d):
    """For each call site in `call_sites`, map a CALLEE-space expression (a bare
    parameter name, or one field-access hop off one, e.g. `data->len`) into that
    site's own CALLER-space expression, by substituting the base identifier through
    the actual-to-formal mapping (matched by argument INDEX, never by guessing).
    Returns a list aligned with `call_sites`, with None at any position where the
    expression's base isn't a recognized parameter of this callee, or isn't passed
    at that particular site."""
    m = re.match(r'^([A-Za-z_]\w*)((?:->|\.)[A-Za-z_]\w*)*$', expr or '')
    if not m:
        return [None] * len(call_sites)
    base, rest = m.group(1), (expr[len(m.group(1)):] if m.group(1) else '')
    out = []
    for site in call_sites:
        mapping = build_actual_to_formal_mapping(d, site, callee_fn)
        caller_base = mapping.get(base)
        out.append((caller_base + rest) if caller_base is not None else None)
    return out

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')
NAME_CHAIN = r'[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*'
CMP_PAIR_RE = re.compile(r'^\s*(' + NAME_CHAIN + r')\s*[<>]=?\s*(' + NAME_CHAIN + r')\s*$')


def emit_candidates(prefix):
    d = json.load(open(prefix))
    calls = d.get('calls', [])
    functions = d.get('functions', [])
    func_by_id = {f.get('id'): f for f in functions}

    extents = compute_allocation_extents(d)
    free_sites = compute_free_sites(d)
    cfg_index = build_cfg_index(d)
    if not extents:
        return []

    assert_codes = [(c.get('code') or '') for c in calls
                     if c.get('name') in ASSERT_NAMES
                     or (c.get('code', '').split('(')[0].strip() in ASSERT_NAMES)]
    # Identity-based, not text-based -- see call_context_guard._collect_assert_arg_ids
    # for why a pure substring check on an assert macro's own rendered `code` is
    # unsound (a real bug found on NSS rsapkcs.c: PR_ASSERT's inner-macro expansion
    # diverges from the same comparison node's own unexpanded `code`).
    assert_ids = _collect_assert_arg_ids(d)

    def _in_assert(call):
        if assert_ids and call.get('id') in assert_ids:
            return True
        cc = (call.get('code') or '').strip()
        return bool(cc) and any(cc in ac for ac in assert_codes)

    # guarded_pairs_by_fn[fn] = {frozenset({width_expr, cap_expr}), ...} -- a
    # non-assert comparison directly relating a width expression to a capacity's
    # symbolic size_expression, in either order.
    guarded_pairs_by_fn = {}
    for c in calls:
        if c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        if _in_assert(c):
            continue
        m = CMP_PAIR_RE.match(code)
        if not m:
            continue
        fn = c.get('enclosing_function_id')
        guarded_pairs_by_fn.setdefault(fn, set()).add(frozenset((m.group(1), m.group(2))))

    # scalar_defs[(fn, name)] = defining RHS expression, for ONE-HOP resolution of
    # a capacity's size_expression when it's itself a bare variable defined
    # earlier as an arithmetic expression (e.g. `buffer_len = SharedSecret->len +
    # 4 + SharedInfoLen; buffer = PORT_Alloc(buffer_len);` -- the AllocationExtentFact
    # faithfully records size_expression="buffer_len" (that IS what was passed to
    # the allocator), but the safety checks below need the EXPANDED definition to
    # recognize `SharedSecret->len` as a safe additive term of it). Deliberately
    # narrow: only a bare-identifier LHS assigned a NON-call, NON-bare-identifier
    # RHS (i.e. a plain arithmetic expression, not another alias or a call) is
    # captured, and only ONE hop is resolved -- this is a safety-check
    # convenience, not a general expression-propagation engine.
    scalar_defs = {}
    for c in calls:
        if c.get('name') != '<operator>.assignment':
            continue
        code = c.get('code') or ''
        sm = re.match(r'^\s*([A-Za-z_]\w*)\s*=\s*(.+)$', code)
        if not sm:
            continue
        rhs = sm.group(2).strip()
        if re.fullmatch(r'[A-Za-z_]\w*', rhs) or '(' in rhs:
            continue   # a plain alias or a call -- not a scalar arithmetic def
        fn = c.get('enclosing_function_id')
        scalar_defs[(fn, sm.group(1))] = rhs

    def _safety_expressions(fn, size_expr):
        """The capacity expression itself, plus its one-hop scalar expansion when
        available -- both are checked by the safety rules below."""
        exprs = [size_expr]
        if re.fullmatch(r'[A-Za-z_]\w*', size_expr) and (fn, size_expr) in scalar_defs:
            exprs.append(scalar_defs[(fn, size_expr)])
        return exprs

    ops = []
    for c in calls:
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is None:
            continue
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        da, wa = contract['dest_arg'], contract['width_arg']
        if da >= len(args) or wa >= len(args):
            continue
        ops.append({'call_id': c.get('id'), 'function_id': c.get('enclosing_function_id'),
                     'file': c.get('file'), 'line': c.get('line'), 'callee': callee,
                     'dest_code': (args[da].get('code') or '').strip(),
                     'width_code': (args[wa].get('code') or '').strip(),
                     'contract_source': contract['source']})

    cand = []
    seen = set()
    for op in ops:
        fn = op['function_id']
        dest_code, len_code = op['dest_code'], op['width_code']
        if not re.fullmatch(r'[A-Za-z_]\w*', dest_code):
            continue   # bare pointer destination only, for this MVP
        extent = extents.get((fn, dest_code))
        if extent is None:
            continue   # no runtime-capacity fact for this pointer -- abstain
        if extent['establishment_status'] != 'ESTABLISHED':
            continue
        free_ids = free_sites.get((fn, dest_code), [])
        sink_status = capacity_status_at_sink(cfg_index, fn, extent['allocation_site'],
                                              free_ids, op['call_id'])
        if sink_status != 'ESTABLISHED':
            continue   # INVALID (a free provably precedes this write) or AMBIGUOUS
                       # (a free MIGHT precede it on some path) or UNKNOWN (no CFG
                       # data to reason with) -- none of these let this pass
                       # confidently use the capacity at THIS specific write
        N = extent.get('extent_in_bytes')
        size_expr = extent['size_expression']
        # provably safe by pure arithmetic, no guess involved
        if N is not None and re.fullmatch(r'\d+', len_code) and int(len_code) <= N:
            continue
        safe = False
        for expr in _safety_expressions(fn, size_expr):
            # The write width is the EXACT SAME expression as the capacity (or its
            # one-hop scalar expansion) -- e.g. `tmpOutput = PORT_Alloc(inputLen);
            # PORT_Memcpy(tmpOutput, in, inputLen);` -- allocated and copied are
            # textually identical -- safe by construction, no guess involved. No
            # arithmetic is being reasoned about here at all (it's x <= x), so this
            # is sound regardless of overflow, sign, or units. Found as a real
            # false positive testing against NSS rsapkcs.c before this check
            # existed.
            if len_code == expr:
                safe = True
                break
        if safe:
            continue
        # REMOVED (soundness bug, caught before shipping further): an earlier
        # version of this check treated the write width as safe whenever it was
        # exactly ONE ADDEND of a pure `a + b + ...` capacity expression (e.g.
        # `buffer_len = SharedSecret->len + 4 + SharedInfoLen; PORT_Memcpy(buffer,
        # ..., SharedSecret->len)`). That is NOT generally safe in C: unsigned
        # `x + y` can WRAP to a value SMALLER than `x` (if `y` is large enough,
        # attacker-influenced, or itself computed from unchecked input), which
        # means `capacity = x + y; memcpy(p, src, x)` can allocate the wrapped
        # (small) capacity and then copy `x` bytes -- exactly the overflow shape
        # this producer exists to catch. Concretely: `SharedInfoLen` here is a
        # caller-supplied `CK_ULONG` with no bound check before the addition --
        # this pass has no way to rule out `SharedSecret->len + 4 + SharedInfoLen`
        # wrapping. "Checking only for subtraction does not establish addition
        # safety" -- proving one addend fits within a sum requires (a) every
        # OTHER addend is nonnegative, (b) the sum cannot overflow/wrap, (c)
        # compatible units, none of which this pass establishes. Without that
        # evidence the verdict must remain a CANDIDATE, not silently safe.
        # No replacement rule is added in its place: an addend-of-a-sum is
        # UNRESOLVED-to-safety by default now, which in this pass's vocabulary
        # means it falls through to CANDIDATE below, same as any other unproven
        # write -- exactly the "if in doubt, flag, never assume safe" posture
        # every other producer in this family already follows.
        # a real (non-assert) guard directly relates the width to this capacity
        pair = frozenset((len_code, size_expr))
        if pair in guarded_pairs_by_fn.get(fn, set()):
            continue
        # CALLER-CONTEXT GUARD SUPPRESSION (round 13): no local guard exists in
        # THIS function -- check whether every statically-resolved call site
        # reaching it has a caller-side guard protecting the SAME relationship,
        # mapped into each caller's own argument expressions. Suppress only if
        # call sites exist AND every single one is CREDITED; per-call-site
        # evidence, never merged into one function-wide conclusion.
        call_sites = find_call_sites(d, fn)
        if call_sites:
            w_caller = _map_expr_to_caller_space(len_code, fn, call_sites, d)
            c_caller = _map_expr_to_caller_space(size_expr, fn, call_sites, d)
            if w_caller is not None and c_caller is not None:
                all_credited = True
                for site, w_expr, c_expr in zip(call_sites, w_caller, c_caller):
                    if w_expr is None or c_expr is None:
                        all_credited = False
                        break
                    guard_fact = guard_status_for_call(d, cfg_index, site, w_expr, c_expr,
                                                        assert_codes, assert_ids)
                    if guard_fact['establishment_status'] != 'CREDITED':
                        all_credited = False
                        break
                if all_credited:
                    continue   # every reaching call site independently proves this bounded
        key = (fn, dest_code, len_code, op['call_id'])
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(fn) or {}
        cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'RUNTIME_CAPACITY',
                     'callee': op['callee'], 'contract_source': op['contract_source'],
                     'dest': dest_code, 'size_expression': size_expr, 'extent_in_bytes': N,
                     'width_expr': len_code, 'provenance': extent['provenance'],
                     'file': op['file'], 'function': _fn.get('full_name'),
                     'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                     'function_id': fn, 'line': op['line'],
                     'derivation': {'rule': 'CPP_RUNTIME_ALLOCATION_CAPACITY_UNBOUNDED',
                                    'capacity_source': 'ALLOCATION_EXTENT_FACT'}})
    return cand


if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'RUNTIME_CAPACITY candidate(s)')
        for x in c:
            print('   ', x['callee'], '(', x['dest'], ',.., ', x['width_expr'], ') capacity=',
                  x['size_expression'], '(', x['extent_in_bytes'], 'bytes)',
                  'via', x['provenance'], '@L', x.get('line'))
