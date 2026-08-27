#!/usr/bin/env python3
"""Runtime allocation-capacity tracking -- a shared fact-derivation module (not a
verdict producer itself) consumed by oob_runtime_capacity_verdict.py. Establishes
AllocationExtentFact records:

    AllocationExtentFact
      allocation_site      -- call id of the ORIGINAL allocation (preserved through
                               propagation, not overwritten at each hop)
      allocated_pointer    -- pointer name, meaningful only paired with function_id
      size_expression      -- the byte-size expression AS TEXT (may be symbolic,
                               e.g. "modulusLen" -- this module does not require a
                               literal to establish a fact; a symbolic capacity is
                               still useful for TEXTUAL guard-matching downstream)
      element_width        -- 1 for a simple/realloc allocation (already byte
                               units); the literal width for a calloc-shaped
                               product, when known
      extent_in_bytes      -- a literal int IF size_expression folds to a constant,
                               else None (symbolic-only fact, still ESTABLISHED)
      provenance           -- short derivation-chain string (direct_allocation,
                               alias_of:.., offset_from:.., propagated_call:..)
      establishment_status -- 'ESTABLISHED' | 'AMBIGUOUS' | 'UNRESOLVED'

Relationships established:
    p = malloc(n);            -> capacity(p) = n bytes           (kind: simple)
    p = calloc(count, width); -> capacity(p) = count * width bytes, ONLY when both
                                  count and width fold to literal constants --
                                  "Potential multiplication overflow must not be
                                  treated as an established capacity": a SYMBOLIC
                                  count or width means the product could overflow
                                  size_t in ways this pass has no way to rule out,
                                  so the fact is UNRESOLVED, not guessed at.

Preserved through, and ONLY through, these VERIFIED operations:
  1. Direct assignment and supported casts:      q = p;  q = (T*)p;
  2. Pointer aliases with established identity:  same as #1, chained to a fixed
     point (bounded hops) within one function.
  3. Pointer-plus-offset derivations:            q = p + k;  -- tracked as an
     OFFSET annotation on the SAME underlying extent fact, never collapsed into a
     smaller numeric extent unless BOTH the base extent and the offset are literal
     (matches the same posture already used by oob_copy_length_verdict.py's
     round-4 pointer-offset extension: widen WHERE capacity is visible, don't
     invent arithmetic precision this pass can't prove).
  4. A single statically-resolved call edge:     reuses the exact same mechanism as
     oob_interprocedural_verdict.py (`candidate_target_ids` + `resolution ==
     'EXACT'`), generalized to carry a (possibly symbolic) extent instead of only a
     literal one. Two call sites disagreeing on a callee parameter's extent ->
     AMBIGUOUS, dropped, not guessed at -- identical posture to round 8.
  5. A struct-field store, ONLY when the field identity is independently confirmed
     reliable in the exported facts -- NOT IMPLEMENTED in this first version. Round
     10 found a real case (NSS CVE-2021-43527's anonymous union) where Joern's CPG
     export itself silently drops a struct/union member fact; trusting a
     `members`-fact lookup without a reliability check would risk exactly that
     failure mode silently. Deferred rather than built on unverified ground; a
     struct-field-store destination remains UNRESOLVED for now (the module simply
     does not attempt this shape at all).

Conservative handling, exactly as specified:
  - `realloc(p, n)` REPLACES p's previous extent fact entirely (a fresh
    `size_expression = n`), not merged with it.
  - `free(p)` INVALIDATES p's extent for the rest of ITS function -- implemented at
    the same whole-function granularity already used throughout this producer
    family (if `free(p)`/`PORT_Free(p)` appears ANYWHERE in the function, no extent
    is ever established for `p` in that function; this is coarser than true
    control-flow-ordering, deliberately conservative, matches the family's
    documented dominance-unaware guard-crediting precedent).
  - Two DIFFERENT direct allocations to the SAME (function, pointer) name with
    DIFFERENT size expressions -> AMBIGUOUS, no fact established for that key.
  - An allocator call not in `allocator_contracts.ALLOCATOR_CONTRACTS` establishes
    nothing at all -- unknown/custom allocators remain UNRESOLVED structurally
    (the lookup returns nothing), never guessed at via a declarative contract this
    module doesn't have.
"""
import re
from allocator_contracts import ALLOCATOR_CONTRACTS, FREE_FUNCS


def _eval_const_int_expr(expr):
    e = (expr or '').strip()
    if not e or not re.fullmatch(r'[\d\s+\-*/()]+', e):
        return None
    try:
        v = eval(e, {'__builtins__': {}}, {})
    except Exception:
        return None
    return v if isinstance(v, int) and v >= 0 else None


ALIAS_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?([A-Za-z_]\w*)\s*$')
OFFSET_ALIAS_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?([A-Za-z_]\w*)\s*\+\s*(.+)$')


def _fact(site, ptr, size_expr, elem_w, extent, provenance, status):
    return {'allocation_site': site, 'allocated_pointer': ptr, 'size_expression': size_expr,
            'element_width': elem_w, 'extent_in_bytes': extent, 'provenance': provenance,
            'establishment_status': status, 'offset_expression': None}


def compute_allocation_extents(d):
    """Returns {(function_id, pointer_name): AllocationExtentFact} for every pointer
    this module can establish a fact for, across the whole file. AMBIGUOUS/freed
    keys are simply absent (never returned), same "abstain rather than guess"
    posture as everywhere else in this producer family."""
    calls = d.get('calls', [])
    functions = d.get('functions', [])
    assign_calls = [c for c in calls if c.get('name') == '<operator>.assignment']

    # --- direct allocations -------------------------------------------------
    direct = {}       # (fn, ptr) -> fact
    conflicted = set()
    freed = set()      # (fn, ptr) with a free() call anywhere in the function

    for c in calls:
        if c.get('name') in FREE_FUNCS or (c.get('method_full_name') in FREE_FUNCS):
            args = c.get('arguments', [])
            if args:
                pname = (args[0].get('code') or '').strip()
                if re.fullmatch(r'[A-Za-z_]\w*', pname):
                    freed.add((c.get('enclosing_function_id'), pname))

    for c in assign_calls:
        m = ALIAS_RE.match(c.get('code') or '')
        # Not an alias -- check if RHS is itself an allocator call by inspecting
        # the callee name embedded in the assignment's own call fact set. Joern
        # represents `p = malloc(n);` as an <operator>.assignment whose CODE
        # contains the call text; the actual call site is a SEPARATE call fact at
        # the same line. We match on the assignment's code text directly instead,
        # since that's what's reliably available across this repo's fact shape.
        alloc_m = re.match(
            r'^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?([A-Za-z_]\w*)\s*\(\s*(.*?)\s*\)\s*$',
            c.get('code') or '')
        if not alloc_m:
            continue
        ptr, func_name, argtext = alloc_m.group(1), alloc_m.group(2), alloc_m.group(3)
        contract = ALLOCATOR_CONTRACTS.get(func_name)
        if contract is None:
            continue   # unknown allocator -- unresolved, structurally
        fn = c.get('enclosing_function_id')
        # naive top-level comma split -- sufficient for the shapes this module
        # targets (allocator arguments are simple expressions, not nested calls
        # with their own commas, in every real case checked so far)
        args = [a.strip() for a in argtext.split(',')] if argtext else []

        if contract['kind'] == 'simple':
            if contract['size_arg'] >= len(args):
                continue
            size_expr = args[contract['size_arg']]
            extent = _eval_const_int_expr(size_expr)
            fact = _fact(c.get('id'), ptr, size_expr, 1, extent, 'direct_allocation', 'ESTABLISHED')
        elif contract['kind'] == 'product':
            if contract['count_arg'] >= len(args) or contract['width_arg'] >= len(args):
                continue
            count_expr, width_expr = args[contract['count_arg']], args[contract['width_arg']]
            count_n, width_n = _eval_const_int_expr(count_expr), _eval_const_int_expr(width_expr)
            if count_n is None or width_n is None:
                # Symbolic multiplication -- overflow cannot be ruled out. Per
                # spec: never treat this as an established capacity.
                continue
            fact = _fact(c.get('id'), ptr, f'{count_expr}*{width_expr}', width_n,
                         count_n * width_n, 'direct_allocation_product', 'ESTABLISHED')
        elif contract['kind'] == 'realloc':
            if contract['size_arg'] >= len(args):
                continue
            size_expr = args[contract['size_arg']]
            extent = _eval_const_int_expr(size_expr)
            # realloc REPLACES the previous extent entirely -- a fresh fact,
            # never merged with whatever `direct` already held for this key.
            fact = _fact(c.get('id'), ptr, size_expr, 1, extent, 'realloc_replaces_prior', 'ESTABLISHED')
        else:
            continue

        key = (fn, ptr)
        if key in conflicted:
            continue
        if key in direct and (direct[key]['size_expression'] != fact['size_expression']
                               or direct[key]['provenance'] == 'realloc_replaces_prior'):
            if direct[key]['provenance'] == 'realloc_replaces_prior' or fact['provenance'] == 'realloc_replaces_prior':
                direct[key] = fact   # realloc wins over a prior plain allocation
                continue
            # two DIFFERENT direct allocations, different sizes -> ambiguous
            conflicted.add(key)
            direct.pop(key, None)
            continue
        direct[key] = fact

    for key in list(direct):
        if key in freed:
            direct.pop(key)   # free() anywhere in the function invalidates it

    # --- alias propagation (fixed point, bounded hops) -----------------------
    extents = dict(direct)
    offset_of = {}   # (fn, ptr) -> (base_key, offset_expr) for pointer-plus-offset
    raw_assigns = []
    for c in assign_calls:
        code = c.get('code') or ''
        fn = c.get('enclosing_function_id')
        m = ALIAS_RE.match(code)
        if m and m.group(1) != m.group(2):
            raw_assigns.append(('alias', fn, m.group(1), m.group(2), None))
            continue
        m2 = OFFSET_ALIAS_RE.match(code)
        if m2:
            raw_assigns.append(('offset', fn, m2.group(1), m2.group(2), m2.group(3).strip()))

    for _ in range(4):
        changed = False
        for kind, fn, lhs, rhs, extra in raw_assigns:
            if (fn, lhs) in freed:
                continue
            if kind == 'alias':
                src = extents.get((fn, rhs))
                if src is None:
                    continue
                new_fact = dict(src)
                new_fact['allocated_pointer'] = lhs
                new_fact['provenance'] = f'alias_of:{fn}:{rhs}'
                if extents.get((fn, lhs)) != new_fact:
                    extents[(fn, lhs)] = new_fact
                    changed = True
            else:  # offset
                base_key = (fn, rhs)
                if base_key not in extents:
                    continue
                if offset_of.get((fn, lhs)) != (base_key, extra):
                    offset_of[(fn, lhs)] = (base_key, extra)
                    base = extents[base_key]
                    lit_base, lit_off = base.get('extent_in_bytes'), _eval_const_int_expr(extra)
                    if lit_base is not None and lit_off is not None:
                        extent = max(lit_base - lit_off, 0)
                    else:
                        extent = None   # symbolic offset -- don't invent precision
                    new_fact = _fact(base['allocation_site'], lhs, base['size_expression'],
                                     base['element_width'], extent,
                                     f'offset_from:{fn}:{rhs}+{extra}', 'ESTABLISHED')
                    new_fact['offset_expression'] = extra
                    extents[(fn, lhs)] = new_fact
                    changed = True
        if not changed:
            break

    # --- single-hop interprocedural propagation (mirrors oob_interprocedural_verdict.py) --
    func_by_id = {f.get('id'): f for f in functions}
    params_by_fn = {}
    for f in functions:
        for p in f.get('parameters', []):
            params_by_fn.setdefault(f.get('id'), {})[p.get('index')] = p.get('name')

    propagated = {}
    conflicted_prop = set()
    for c in calls:
        if c.get('resolution') != 'EXACT':
            continue
        targets = c.get('candidate_target_ids') or []
        if len(targets) != 1:
            continue
        callee_fn = targets[0]
        caller_fn = c.get('enclosing_function_id')
        pmap = params_by_fn.get(callee_fn)
        if not pmap:
            continue
        for a in c.get('arguments', []):
            arg_code = (a.get('code') or '').strip()
            if not re.fullmatch(r'[A-Za-z_]\w*', arg_code):
                continue
            src = extents.get((caller_fn, arg_code))
            if src is None:
                continue
            param_name = pmap.get(a.get('index'))
            if param_name is None:
                continue
            key = (callee_fn, param_name)
            new_fact = dict(src)
            new_fact['allocated_pointer'] = param_name
            new_fact['provenance'] = f'propagated_call:{caller_fn}:{c.get("line")}'
            if key in conflicted_prop:
                continue
            if key in propagated and propagated[key]['size_expression'] != new_fact['size_expression']:
                conflicted_prop.add(key)
                propagated.pop(key, None)
                continue
            propagated[key] = new_fact

    for key, fact in propagated.items():
        if key not in extents:   # a function's own local extent always wins
            extents[key] = fact

    return extents
