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

Never emits VULNERABLE; only CANDIDATE. If in doubt, SUPPRESS or ABSTAIN.
"""
import json, re, sys
from callee_contracts import CALLEE_CONTRACTS
from allocation_extent import compute_allocation_extents

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert')
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
    if not extents:
        return []

    assert_codes = [(c.get('code') or '') for c in calls
                     if c.get('name') in ASSERT_NAMES
                     or (c.get('code', '').split('(')[0].strip() in ASSERT_NAMES)]

    def _in_assert(cmp_code):
        cc = (cmp_code or '').strip()
        return bool(cc) and any(cc in ac for ac in assert_codes)

    # guarded_pairs_by_fn[fn] = {frozenset({width_expr, cap_expr}), ...} -- a
    # non-assert comparison directly relating a width expression to a capacity's
    # symbolic size_expression, in either order.
    guarded_pairs_by_fn = {}
    for c in calls:
        if c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        if _in_assert(code):
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
            # textually identical -- safe by construction, no guess involved.
            # Found as a real false positive testing against NSS rsapkcs.c before
            # this check existed.
            if len_code == expr:
                safe = True
                break
            # The write width is exactly ONE ADDEND of a pure `a + b + ...`
            # capacity expression (e.g. `buffer_len = SharedSecret->len + 4 +
            # SharedInfoLen; buffer = PORT_Alloc(buffer_len); PORT_Memcpy(buffer,
            # SharedSecret->data, SharedSecret->len);` -- the width IS one of the
            # terms the capacity was DEFINED as a sum of, one hop back through
            # buffer_len's own scalar definition). Safe by construction PROVIDED
            # the expression is a pure top-level addition chain (no subtraction,
            # which could make another term negative and invalidate the "sum >=
            # any one term" property) -- deliberately restricted to `+`-only
            # splits. Found as a second real false positive testing against NSS
            # pkcs11c.c before this check existed.
            # `->` (pointer member access) contains a literal hyphen but is not
            # subtraction -- strip it before checking, or every struct-field
            # term (e.g. `SharedSecret->len`) would wrongly look like it might
            # involve subtraction. Caught testing this exact real shape.
            if '-' not in expr.replace('->', ''):
                terms = {t.strip() for t in expr.split('+')}
                if len_code in terms:
                    safe = True
                    break
        if safe:
            continue
        # a real (non-assert) guard directly relates the width to this capacity
        pair = frozenset((len_code, size_expr))
        if pair in guarded_pairs_by_fn.get(fn, set()):
            continue
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
