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


# --- Form-aware non-bare destination diagnosis --------------------------------
# A recognized memcpy-family sink whose destination is NOT a bare pointer
# identifier (a struct member, an address-of, pointer arithmetic, a cast, or a
# side-effecting expression). This heap-capacity producer does NOT finalize a
# verdict for such a destination -- it has no capacity SOURCE for non-heap
# objects. It emits an ABSTENTION (or, for a provable overrun, a CANDIDATE never a
# hard verdict) whose reason is chosen from the CPG-RESOLVED form of the
# destination, NOT from the destination text matching a regex. "Identifiable"
# means the base identifier's Joern reference-target resolves to exactly ONE
# declaration node; a fixed extent means that declaration's type is a
# compile-time-sized array or a scalar whose byte size is modeled here.
#
# The frozen V1/V2 boundary is preserved: this V1 producer NEVER promotes a
# non-heap destination to a safe verdict (`deterministic_complete`). A fixed
# extent whose write provably fits is UNDER-CLAIMED (abstained, not promoted); a
# fixed extent whose write provably exceeds is surfaced as an `open_candidate`
# (flag-never-assume-safe), with the computed comparison attached so the
# stack-capacity owner / adjudicator finalizes. No stack/scalar capacity SOURCE is
# introduced into V1's candidate/guard logic -- the comparison lives only in this
# diagnosis layer and is pure literal arithmetic over a CPG-resolved fixed size
# (the same class of sound reasoning as the existing `len<=N` literal check).

OP_ADDR = '<operator>.addressOf'
OP_CAST = '<operator>.cast'
OP_FIELD = ('<operator>.indirectFieldAccess', '<operator>.fieldAccess')
OP_INDEX = ('<operator>.indirectIndexAccess', '<operator>.computedMemberAccess')
OP_ADD = ('<operator>.addition',)
OP_SUB = ('<operator>.subtraction',)
OP_INDIR = ('<operator>.indirection',)
OP_INCDEC = ('<operator>.postIncrement', '<operator>.preIncrement',
             '<operator>.postDecrement', '<operator>.preDecrement')

# Byte sizes for element/scalar types whose width is fixed by the C standard on
# every target this scanner runs against. `long`, `size_t`, pointer types, enums,
# and anything unlisted are DELIBERATELY absent: their size is platform-dependent
# or unknown here, so extent resolution FAILS CLOSED (no comparison is attempted).
_TYPE_BYTES = {
    'char': 1, 'signed char': 1, 'unsigned char': 1, 'int8_t': 1, 'uint8_t': 1,
    'short': 2, 'short int': 2, 'unsigned short': 2, 'int16_t': 2, 'uint16_t': 2,
    'int': 4, 'signed int': 4, 'unsigned int': 4, 'unsigned': 4,
    'int32_t': 4, 'uint32_t': 4, 'float': 4,
    'long long': 8, 'long long int': 8, 'unsigned long long': 8,
    'int64_t': 8, 'uint64_t': 8, 'double': 8,
}


def _array_extent(type_full_name):
    """(elem_bytes, count) for a fixed `T[N]` type whose element size is modeled,
    else None. Fails closed on unknown element sizes."""
    m = re.fullmatch(r'(.+?)\s*\[(\d+)\]', (type_full_name or '').strip())
    if not m:
        return None
    es = _TYPE_BYTES.get(m.group(1).strip())
    return (es, int(m.group(2))) if es is not None else None


def _scalar_bytes(type_full_name):
    return _TYPE_BYTES.get((type_full_name or '').strip())


def _is_pointer_type(t):
    return (t or '').strip().endswith('*')


def _build_form_index(d):
    call_by_id = {c.get('id'): c for c in d.get('calls', [])}
    ident_by_id = {}
    for i in d.get('identifiers', []):
        # Same node id may appear under both <global> and its enclosing function;
        # ref_target_ids agree across those copies (verified), so last-wins is safe.
        ident_by_id[i.get('id')] = i
    params_by_id = {}
    for f in d.get('functions', []):
        for p in (f.get('parameters') or []):
            params_by_id[p.get('id')] = (f.get('id'), p)
    locals_by_id = {l.get('id'): l for l in d.get('locals', [])}
    members = d.get('members', [])
    type_decls = d.get('type_decls', [])
    return {'call_by_id': call_by_id, 'ident_by_id': ident_by_id,
            'params_by_id': params_by_id, 'locals_by_id': locals_by_id,
            'members': members, 'type_decls': type_decls}


def _full_node(node, ix):
    """The full CPG node for an argument -- the embedded argument copy omits the
    operator `name`; the calls-list entry carries it."""
    return ix['call_by_id'].get(node.get('id'), node)


def _walk_dest(node, ix, depth=0):
    """Walk a destination expression into a flat descriptor. Returns a dict with
    `kind` in {ident, member, deref, sideeffect, unsupported}. `off` (for ident) is
    an ELEMENT offset into the base array (int, or 'sym'). CAST is transparent
    (unwrapped to its value operand); ADDRESS-OF is transparent (`&X` ~ `X`)."""
    if node is None or depth > 32:
        return {'kind': 'unsupported'}
    n = _full_node(node, ix)
    kind = n.get('kind')
    op = n.get('name') or n.get('method_full_name')
    if kind == 'IDENTIFIER':
        return {'kind': 'ident', 'base': n.get('id'), 'off': 0}
    args = sorted(n.get('arguments', []), key=lambda a: a.get('index', 0))
    if op in OP_INCDEC:
        return {'kind': 'sideeffect'}
    if op == OP_CAST:
        vals = [a for a in args if _full_node(a, ix).get('kind') != 'TYPE_REF']
        return _walk_dest(vals[0], ix, depth + 1) if vals else {'kind': 'unsupported'}
    if op == OP_ADDR:
        return _walk_dest(args[0], ix, depth + 1) if args else {'kind': 'unsupported'}
    if op in OP_FIELD:
        base = _walk_dest(args[0], ix, depth + 1) if args else {'kind': 'unsupported'}
        fa = _full_node(args[1], ix) if len(args) > 1 else {}
        return {'kind': 'member', 'baseobj': base,
                'field': fa.get('code') or fa.get('name')}
    if op in OP_INDEX:
        base = _walk_dest(args[0], ix, depth + 1) if args else {'kind': 'unsupported'}
        ia = _full_node(args[1], ix) if len(args) > 1 else {}
        if base.get('kind') != 'ident':
            return {'kind': 'unsupported'}
        idx = (int(ia['code']) if ia.get('kind') == 'LITERAL'
               and re.fullmatch(r'\d+', (ia.get('code') or '').strip()) else 'sym')
        return {'kind': 'ident', 'base': base['base'], 'off': idx}
    if op in OP_ADD or op in OP_SUB:
        base = _walk_dest(args[0], ix, depth + 1) if args else {'kind': 'unsupported'}
        oa = _full_node(args[1], ix) if len(args) > 1 else {}
        if base.get('kind') != 'ident':
            return {'kind': 'unsupported'}
        if oa.get('kind') == 'LITERAL' and re.fullmatch(r'\d+', (oa.get('code') or '').strip()):
            off = int(oa['code'])
            if op in OP_SUB:
                off = -off
        else:
            off = 'sym'
        return {'kind': 'ident', 'base': base['base'], 'off': off}
    if op in OP_INDIR:
        base = _walk_dest(args[0], ix, depth + 1) if args else {'kind': 'unsupported'}
        return {'kind': 'deref', 'baseobj': base}
    return {'kind': 'unsupported'}


def _resolve_object(ident_id, ix):
    """Resolve a base IDENTIFIER node to its declaration via the CPG reference
    target. Returns {'type', 'src', 'decl'} or None when the reference does not
    resolve to exactly one declaration (unresolved / ambiguous)."""
    ident = ix['ident_by_id'].get(ident_id)
    if not ident:
        return None
    refs = ident.get('ref_target_ids') or []
    if len(refs) != 1:
        return None
    decl = refs[0]
    if decl in ix['params_by_id']:
        _, p = ix['params_by_id'][decl]
        return {'type': p.get('type_full_name'), 'src': 'param', 'decl': decl}
    l = ix['locals_by_id'].get(decl)
    if l is not None:
        return {'type': l.get('type_full_name'), 'src': 'local', 'decl': decl}
    return None


def _member_type(struct_ptr_type, field, ix):
    """The declared type of `field` in the struct named by `struct_ptr_type` (e.g.
    'S*' or 'S'), via the CPG member declarations. None if the struct/field is not
    found or the member type is ambiguous across same-named type decls (fail
    closed -- never guess an extent)."""
    base = (struct_ptr_type or '').strip().rstrip('*').strip()
    base = re.sub(r'^(struct|union)\s+', '', base)
    if not base or not field:
        return None
    tds = {t.get('id') for t in ix['type_decls'] if t.get('name') == base}
    types = {m.get('type_full_name') for m in ix['members']
             if m.get('name') == field and m.get('type_decl_id') in tds}
    return types.pop() if len(types) == 1 else None


def _abstain_fields(reason, base, extra):
    """Fill the frozen reason-emission fields for an abstention/candidate record."""
    base['reason_code'] = reason
    base['primary_reason_code'] = reason
    base['all_reason_codes'] = [reason]
    base['uncertainty_bucket'] = bucket_for_reason(reason)
    base['recommended_route'] = route_for_reason(reason)
    base['unresolved_property'] = property_for_reason(reason)
    base['llm_eligible'] = llm_eligible_for_reason(reason)
    base.update(extra)
    return base


def diagnose_nonbare_destination(dest_arg_node, width_code, ix, base):
    """Classify a recognized-but-non-bare memcpy destination by its CPG-resolved
    form and populate `base` with the correct abstention/candidate record. Returns
    `base`. Mapping (see module note):
      * identity unresolvable / side-effecting  -> destination_identity_ambiguous
      * identity known, no fixed extent          -> required_evidence_absent
      * fixed extent, symbolic offset/width      -> capacity_relation_not_established
      * fixed extent, literal offset+width, fits -> capacity_relation_not_established
                                                    (abstained; comparison attached)
      * fixed extent, literal offset+width, over -> capacity_relation_not_established
                                                    (open_candidate; comparison attached)
    """
    w = _walk_dest(dest_arg_node, ix)
    kind = w.get('kind')

    def ambiguous(form):
        base['analysis_status'] = 'abstained'
        base['destination_form'] = form
        base['missing_requirement'] = 'destination_object_identity'
        return _abstain_fields('destination_identity_ambiguous', base, {})

    def evidence_absent(form):
        base['analysis_status'] = 'abstained'
        base['destination_form'] = form
        base['missing_requirement'] = 'destination_capacity'
        return _abstain_fields('required_evidence_absent', base, {})

    def fixed(extent, elem, off_elems, form_prefix):
        """A CPG-resolved fixed-extent object. Compute the remaining-capacity
        comparison when offset and width are literal; otherwise the relation is
        unresolved. Never promotes to a safe verdict; a provable overrun becomes an
        open_candidate."""
        if off_elems == 'sym':
            base['analysis_status'] = 'abstained'
            return _abstain_fields('capacity_relation_not_established', base, {
                'destination_form': 'fixed_extent_symbolic_relation',
                'destination_fixed_extent_bytes': extent})
        byte_off = off_elems * (elem or 1)
        remaining = extent - byte_off
        if byte_off < 0 or not re.fullmatch(r'\d+', (width_code or '').strip()):
            # negative/symbolic offset or symbolic width: relation not established
            base['analysis_status'] = 'abstained'
            return _abstain_fields('capacity_relation_not_established', base, {
                'destination_form': form_prefix + '_symbolic_relation',
                'destination_fixed_extent_bytes': extent})
        width = int(width_code)
        fits = width <= remaining
        comparison = {'destination_fixed_extent_bytes': extent, 'byte_offset': byte_off,
                      'write_width_bytes': width, 'remaining_capacity_bytes': remaining,
                      'write_fits': fits}
        base['analysis_status'] = 'open_candidate' if not fits else 'abstained'
        base['destination_form'] = (form_prefix + '_write_exceeds_bounds' if not fits
                                    else form_prefix + '_write_within_bounds')
        base['capacity_comparison'] = comparison
        # `capacity_relation_not_established` names it precisely in BOTH directions:
        # the SAFE relation (width<=capacity) is either disproven (overrun -> flagged
        # candidate) or established-but-not-finalized-here (fits -> under-claimed
        # abstention, preserving the heap-only-finalization boundary).
        return _abstain_fields('capacity_relation_not_established', base,
                               {'established_facts': [comparison]})

    if kind == 'sideeffect':
        return ambiguous('side_effecting_expression')
    if kind in ('unsupported', 'deref'):
        return ambiguous('unsupported_expression')
    if kind == 'member':
        bo = w.get('baseobj') or {}
        if bo.get('kind') != 'ident':
            return ambiguous('unresolved_member_base')
        obj = _resolve_object(bo.get('base'), ix)
        if obj is None:
            return ambiguous('unresolved_reference')
        mt = _member_type(obj.get('type'), w.get('field'), ix)
        if mt is None:
            return evidence_absent('member_extent_unknown')
        if _is_pointer_type(mt):
            return evidence_absent('pointer_member')
        arr = _array_extent(mt)
        if arr is not None:
            return fixed(arr[0] * arr[1], arr[0], 0, 'fixed_array_member')
        sb = _scalar_bytes(mt)
        if sb is not None:
            return fixed(sb, sb, 0, 'scalar_member')
        return evidence_absent('member_extent_unknown')
    # ident-based (array / scalar / pointer, with an optional element offset)
    obj = _resolve_object(w.get('base'), ix)
    if obj is None:
        return ambiguous('unresolved_reference')
    t = obj.get('type')
    if _is_pointer_type(t):
        return evidence_absent('pointer_object')
    arr = _array_extent(t)
    if arr is not None:
        return fixed(arr[0] * arr[1], arr[0], w.get('off', 0), 'fixed_array_object')
    sb = _scalar_bytes(t)
    if sb is not None:
        return fixed(sb, sb, w.get('off', 0), 'scalar_object')
    return evidence_absent('object_extent_unknown')


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
    form_index = _build_form_index(d)

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
                    'width_code': (args[wa].get('code') or '').strip(),
                    'dest_arg': args[da]})

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
            # EMISSION-GAP FIX (FORM-AWARE): a recognized sink (memcpy family) whose
            # destination is not a bare pointer identifier. Previously the operation was
            # silently DROPPED; the first fix collapsed every such case into one
            # `required_evidence_absent`/`member_or_expression` record. That reason was too
            # coarse -- a non-bare text form does NOT prove capacity is absent. The reason is
            # now chosen from the CPG-RESOLVED form of the destination (reference-target /
            # declaration resolution, never a text regex): an unresolved reference or a
            # side-effecting expression is an IDENTITY gap; a resolved pointer object/member
            # is an EVIDENCE gap; a resolved fixed-extent object is a RELATIONSHIP gap whose
            # remaining-capacity comparison is computed when the offset and width are literal.
            # This producer never promotes a non-heap destination to a safe verdict; a
            # provable overrun is surfaced as an open_candidate, never a hard verdict.
            if dest:
                diagnose_nonbare_destination(op.get('dest_arg'), width, form_index, base)
                records.append(base)
            continue   # non-bare destination: recognized, form-aware reason, never promoted safe

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
