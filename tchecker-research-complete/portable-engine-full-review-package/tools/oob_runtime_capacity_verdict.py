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
import hashlib, json, re, sys
from callee_contracts import CALLEE_CONTRACTS
from allocator_contracts import ALLOCATOR_CONTRACTS
from allocation_extent import (compute_allocation_extents, compute_free_sites, build_cfg_index,
                               capacity_status_at_sink, _eval_const_int_expr)
from call_context_guard import (build_actual_to_formal_mapping, guard_status_for_call,
                                 find_call_sites, _collect_assert_arg_ids)
from analysis_record import (primary_reason, bucket_for_reason, route_for_reason,
                             property_for_reason, llm_eligible_for_reason, REASON_DEFINITIONS)


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


def _diagnose_capacity(d, fn, dest):
    """ALL explicit reason codes for why `dest`'s capacity could not be
    established in `fn`, derived from this producer's own allocation-parsing
    signals (NOT inferred from candidate absence). Mirrors
    compute_allocation_extents's direct-allocation parsing so the reasons match
    what actually stopped the fact from being established. Returns a LIST (the
    caller applies analysis_record.primary_reason precedence); the list uses the
    frozen cross-producer reason codes:
      - two different reaching allocation sizes -> conflicting_reaching_allocations
      - a product (calloc-shaped) allocation with a symbolic factor
        -> allocation_overflow_relation_unresolved (a specific arithmetic
           relationship, NOT generic insufficiency)
      - the pointer is assigned from a call to a function with no allocator
        contract -> unknown_allocator_contract
      - none of the above recoverable -> required_evidence_absent (catch-all)"""
    sizes = set()
    saw_symbolic_product = False
    saw_unknown_allocator = False
    saw_known_alloc = False
    for c in d.get('calls', []):
        if c.get('name') != '<operator>.assignment' or c.get('enclosing_function_id') != fn:
            continue
        m = re.match(r'^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?([A-Za-z_]\w*)\s*\(\s*(.*?)\s*\)\s*$',
                     c.get('code') or '')
        if not m or m.group(1) != dest:
            continue
        func_name, argtext = m.group(2), m.group(3)
        contract = ALLOCATOR_CONTRACTS.get(func_name)
        if contract is None:
            saw_unknown_allocator = True
            continue
        saw_known_alloc = True
        args = [a.strip() for a in argtext.split(',')] if argtext else []
        if contract['kind'] == 'product':
            cn = _eval_const_int_expr(args[contract['count_arg']]) if contract['count_arg'] < len(args) else None
            wn = _eval_const_int_expr(args[contract['width_arg']]) if contract['width_arg'] < len(args) else None
            if cn is None or wn is None:
                saw_symbolic_product = True
            else:
                sizes.add(('lit', cn * wn))
        else:  # simple / realloc
            if contract['size_arg'] < len(args):
                sizes.add(('expr', args[contract['size_arg']]))
    reasons = []
    if len(sizes) >= 2:
        reasons.append('conflicting_reaching_allocations')
    if saw_symbolic_product:
        reasons.append('allocation_overflow_relation_unresolved')
    if saw_unknown_allocator and not saw_known_alloc:
        reasons.append('unknown_allocator_contract')
    return reasons or ['required_evidence_absent']


def _record_id(fn, dest, line):
    return 'cand_' + hashlib.sha256(f'{fn}|{dest}|{line}'.encode()).hexdigest()[:16]


def analyze_operations(prefix):
    """Emit one ANALYSIS RECORD per recognized buffer-write operation, with an
    EXPLICIT machine-derived reason_code and (for recognized-but-open/abstained
    cases) the candidate-review bucket + route. This is the reason-emission layer
    the automatic bucket experiment requires: the bucket comes from the reason
    code, not from the mere presence/absence of a candidate.

    Open-candidate determination is delegated to the frozen emit_candidates (no
    duplication of the guard/safety logic); this function only adds the abstention
    diagnosis and the deterministic-complete classification for recognized ops
    that did not become candidates."""
    d = json.load(open(prefix))
    func_by_id = {f.get('id'): f for f in d.get('functions', [])}
    extents = compute_allocation_extents(d)
    free_sites = compute_free_sites(d)
    cfg_index = build_cfg_index(d)

    # recognized buffer-write operations (same contract-driven extraction)
    ops = []
    for c in d.get('calls', []):
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is None:
            continue
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        da, wa = contract['dest_arg'], contract['width_arg']
        if da >= len(args) or wa >= len(args):
            continue
        ops.append({'call_id': c.get('id'), 'function_id': c.get('enclosing_function_id'),
                    'file': c.get('file'), 'line': c.get('line'),
                    'dest_code': (args[da].get('code') or '').strip(),
                    'width_code': (args[wa].get('code') or '').strip()})

    open_keys = {(x['function_id'], x['dest'], x['width_expr'], x['line'])
                 for x in emit_candidates(prefix)}

    records = []
    for op in ops:
        fn, dest, width, line = op['function_id'], op['dest_code'], op['width_code'], op['line']
        fname = (func_by_id.get(fn) or {}).get('full_name')
        _oid = _record_id(fn, dest, line)
        base = {'candidate_id': _oid, 'operation_id': _oid,
                'recognized_operation': 'buffer_write',
                'file': op['file'], 'function': fname, 'line': line,
                'dest': dest, 'width_expr': width}
        if not re.fullmatch(r'[A-Za-z_]\w*', dest):
            # EMISSION-GAP FIX: a recognized sink (memcpy family) whose destination is
            # IDENTIFIABLE but not a bare pointer -- a struct/union member (`p->buf`), an
            # address-of (`&obj`), or pointer arithmetic (`base + off`) -- has no
            # allocation/stack capacity tracked by this producer. Previously the operation was
            # silently DROPPED. Now emit it as an EXPLICIT ABSTENTION so the recognized
            # operation reaches the router with the exact missing requirement named. It is never
            # promoted (this producer does not establish capacity for a non-bare destination).
            if dest:
                base['analysis_status'] = 'abstained'
                base['reason_code'] = 'required_evidence_absent'
                base['primary_reason_code'] = 'required_evidence_absent'
                base['all_reason_codes'] = ['required_evidence_absent']
                base['uncertainty_bucket'] = bucket_for_reason('required_evidence_absent')
                base['recommended_route'] = route_for_reason('required_evidence_absent')
                base['unresolved_property'] = property_for_reason('required_evidence_absent')
                base['llm_eligible'] = llm_eligible_for_reason('required_evidence_absent')
                base['missing_requirement'] = 'destination_capacity'
                base['destination_form'] = 'member_or_expression'
                records.append(base)
            continue   # non-bare destination: recognized + abstained, never promoted

        status = None
        reasons = []
        if (fn, dest, width, line) in open_keys:
            status = 'open_candidate'
            reasons = ['capacity_relation_not_established']
        else:
            extent = extents.get((fn, dest))
            if extent is None or extent.get('establishment_status') != 'ESTABLISHED':
                status = 'abstained'
                reasons = _diagnose_capacity(d, fn, dest)
                if reasons == ['required_evidence_absent']:
                    # name the missing requirement explicitly (bare dest, no reaching allocation)
                    base['missing_requirement'] = 'destination_capacity'
            else:
                sink = capacity_status_at_sink(cfg_index, fn, extent['allocation_site'],
                                               free_sites.get((fn, dest), []), op['call_id'])
                if sink == 'INVALID':
                    # allocation DEFINITELY freed before this write on every path.
                    # NOT a capacity verdict and NOT this producer's to finalize:
                    # emit a HANDOFF to a dedicated lifetime layer.
                    status = 'rerouted'
                    reasons = ['free_dominates_sink']
                elif sink == 'AMBIGUOUS':
                    status = 'abstained'
                    reasons = ['free_may_reach_sink']
                elif sink == 'UNKNOWN':
                    status = 'abstained'
                    reasons = ['required_evidence_absent']
                else:  # ESTABLISHED, not an open candidate -> proven safe/guarded
                    status = 'deterministic_complete'
                    reasons = []

        base['analysis_status'] = status
        if status == 'deterministic_complete':
            base['reason_code'] = None
        elif status == 'rerouted':
            d0 = REASON_DEFINITIONS['free_dominates_sink']
            base.update({'reason_code': 'free_dominates_sink',
                         'primary_reason_code': 'free_dominates_sink',
                         'all_reason_codes': reasons,
                         'uncertainty_bucket': None, 'recommended_route': d0['route'],
                         'candidate_class': d0['candidate_class'], 'llm_eligible': False,
                         'established_facts': ['allocation dominates free', 'free dominates sink',
                                               'destination identity established']})
        else:
            primary = primary_reason(reasons)
            base.update({'reason_code': primary, 'primary_reason_code': primary,
                         'all_reason_codes': reasons,
                         'uncertainty_bucket': bucket_for_reason(primary),
                         'recommended_route': route_for_reason(primary),
                         'unresolved_property': property_for_reason(primary),
                         'llm_eligible': llm_eligible_for_reason(primary)})
        records.append(base)
    return records


if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'RUNTIME_CAPACITY candidate(s)')
        for x in c:
            print('   ', x['callee'], '(', x['dest'], ',.., ', x['width_expr'], ') capacity=',
                  x['size_expression'], '(', x['extent_in_bytes'], 'bytes)',
                  'via', x['provenance'], '@L', x.get('line'))
