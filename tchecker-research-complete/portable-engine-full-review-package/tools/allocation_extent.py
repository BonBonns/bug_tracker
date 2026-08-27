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
  - `free(p)` invalidates p's extent -- CFG-SENSITIVE, per-sink (see
    `capacity_status_at_sink` below), not whole-function. An EARLIER version of
    this module invalidated `p` for its ENTIRE function whenever `free(p)`
    appeared anywhere in it, which is sound (never wrongly credits a freed
    buffer) but was shown to cost real coverage: NSS CVE-2019-17006's
    `rsa_FormatOneBlock` frees `block` on FOUR early-return error paths, all of
    which return before ever reaching the real write -- whole-function
    invalidation suppressed a legitimate candidate for that reason alone, not a
    guard/capacity gap. Replaced with dominance-based reasoning over this
    repo's own `cfg_edges` facts (see `capacity_status_at_sink`): a free only
    invalidates a capacity at a SPECIFIC write when that free is GUARANTEED to
    execute between the allocation and that write on every control-flow path
    (dominance-based, not source-line order -- a `goto` that reorders text
    doesn't change graph reachability). A free that's only POSSIBLE on some
    paths to the write (a conditional free that rejoins before the write)
    yields AMBIGUOUS, not ESTABLISHED -- this pass does not confidently credit
    a capacity that might already be freed, but also does not attempt to flag
    the possible use-after-free itself (a different property, explicitly out
    of scope this session, per the original strategic redirect deferring UAF
    work as "too large an architectural lift").
  - Two DIFFERENT direct allocations to the SAME (function, pointer) name with
    DIFFERENT size expressions -> AMBIGUOUS, no fact established for that key.
  - An allocator call not in `allocator_contracts.ALLOCATOR_CONTRACTS` establishes
    nothing at all -- unknown/custom allocators remain UNRESOLVED structurally
    (the lookup returns nothing), never guessed at via a declarative contract this
    module doesn't have.

ADDITIVE-EXPRESSION SAFETY -- NOT handled by this module at all (moved here from a
prior, INCORRECT version): whether a write width that is one ADDEND of a capacity's
`a + b + ...` defining sum is "safe" is a question this module deliberately does
NOT answer, because it is NOT generally true in C. Unsigned `x + y` can WRAP to a
value SMALLER than `x` (if `y` is large, attacker-influenced, or otherwise
unbounded), so `capacity = x + y; memcpy(p, src, x)` is not safe without INDEPENDENT
evidence that (a) every other addend is nonnegative, (b) the sum cannot
overflow/wrap, and (c) all terms use compatible units -- none of which this module
establishes. `oob_runtime_capacity_verdict.py` (the consumer) only ever treats an
EXACT textual match between a write width and a capacity expression as automatically
safe (x <= x, no arithmetic involved at all); an earlier version additionally
credited "one addend of a pure-addition sum" as safe, which was unsound (caught
before it shipped further -- see that module's own history) and has been removed.
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


def compute_free_sites(d):
    """Returns {(function_id, pointer_name): [free_call_id, ...]} -- every
    free/PORT_Free call site per (function, pointer), WITHOUT judging relevance to
    any particular write yet. Consumed by `capacity_status_at_sink` for CFG-aware,
    per-sink reasoning instead of blanket whole-function invalidation."""
    sites = {}
    for c in d.get('calls', []):
        if c.get('name') in FREE_FUNCS or (c.get('method_full_name') in FREE_FUNCS):
            args = c.get('arguments', [])
            if args:
                pname = (args[0].get('code') or '').strip()
                if re.fullmatch(r'[A-Za-z_]\w*', pname):
                    sites.setdefault((c.get('enclosing_function_id'), pname), []).append(c.get('id'))
    return sites


def build_cfg_index(d):
    """Returns {function_id: {'succ': {node: {succs}}, 'preds': {node: {preds}},
    'nodes': {node,...}, 'entries': {node,...}, 'dom': {node: {dominators}}}} from
    this repo's `cfg_edges` facts. `dom[n]` is the set of nodes that dominate `n`
    (every path from an entry to `n` passes through each of them), computed by
    standard iterative dataflow to a fixed point -- correct for cyclic/irreducible
    graphs, not just simple ones; a `goto` is just another edge in this graph, so
    reordering source text has no effect on the result. Bounded iteration count as
    a hard safety cap, same posture as the reaching-def worklist elsewhere in this
    codebase's normalizer."""
    per_fn = {}
    for e in d.get('cfg_edges', []):
        fn = e.get('function_id')
        a, b = e.get('node_id'), e.get('successor_id')
        if a is None or b is None:
            continue
        g = per_fn.setdefault(fn, {'succ': {}, 'preds': {}, 'nodes': set()})
        g['succ'].setdefault(a, set()).add(b)
        g['preds'].setdefault(b, set()).add(a)
        g['nodes'].add(a)
        g['nodes'].add(b)

    for fn, g in per_fn.items():
        nodes = g['nodes']
        entries = {n for n in nodes if not g['preds'].get(n)}
        g['entries'] = entries
        dom = {n: (set(nodes) if n not in entries else {n}) for n in nodes}
        guard = 0
        changed = True
        while changed and guard < 100000:
            guard += 1
            changed = False
            for n in nodes:
                if n in entries:
                    continue
                ps = g['preds'].get(n)
                if not ps:
                    continue
                new_dom = None
                for p in ps:
                    pd = dom.get(p, nodes)
                    new_dom = set(pd) if new_dom is None else (new_dom & pd)
                new_dom = (new_dom or set()) | {n}
                if new_dom != dom[n]:
                    dom[n] = new_dom
                    changed = True
        g['dom'] = dom
    return per_fn


def _reachable_from(succ, start):
    seen, stack = set(), [start]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for s in succ.get(n, ()):
            if s not in seen:
                stack.append(s)
    return seen


def capacity_status_at_sink(cfg_index, fn, alloc_site, free_ids, sink_id):
    """The CFG-sensitive replacement for whole-function free invalidation.
    Returns 'ESTABLISHED' | 'INVALID' | 'AMBIGUOUS' | 'UNKNOWN' (the last only when
    this function's CFG data is missing/insufficient to reason at all -- treated by
    the caller the same as INVALID: fail closed, never credit a capacity this
    module can't actually verify).

    For each free in `free_ids`:
      - free DOMINATES sink AND alloc DOMINATES free  => that free is guaranteed to
        execute, in order, between the allocation and this specific write on EVERY
        path => INVALID (the capacity cannot be trusted at this sink at all).
      - free is reachable from alloc, and sink is reachable from free (a possible
        alloc -> free -> sink path exists) but the dominance condition above does
        NOT hold (so some OTHER path also reaches sink without the free, e.g. a
        conditional free that rejoins before the write) => AMBIGUOUS.
      - otherwise (the free lies on no alloc->sink path at all -- e.g. an
        error-branch free that returns before ever reaching this write, or a free
        occurring textually/structurally AFTER this sink) => irrelevant to this
        sink, no effect.
    INVALID from any one free wins over AMBIGUOUS from another; AMBIGUOUS wins over
    a clean ESTABLISHED. If `alloc_site` belongs to a DIFFERENT function than `fn`
    (the extent was propagated across a call edge -- see
    oob_interprocedural_verdict.py's single-hop mechanism), the callee's own
    function ENTRY stands in for "the allocation point": a parameter's value is
    available from entry onward, so entry dominance is the correct question."""
    if not free_ids:
        return 'ESTABLISHED'
    g = cfg_index.get(fn)
    if not g or sink_id not in g['nodes']:
        return 'UNKNOWN'
    dom, succ, nodes = g['dom'], g['succ'], g['nodes']
    if alloc_site in nodes:
        alloc_node = alloc_site
    elif g['entries']:
        alloc_node = next(iter(g['entries']))   # propagated extent -- use entry
    else:
        return 'UNKNOWN'
    alloc_reach = _reachable_from(succ, alloc_node)
    status = 'ESTABLISHED'
    for free_id in free_ids:
        if free_id not in nodes:
            continue   # this free isn't even in this function's CFG -- irrelevant
        sink_dom = dom.get(sink_id, set())
        free_dom = dom.get(free_id, set())
        if free_id in sink_dom and alloc_node in free_dom:
            return 'INVALID'   # guaranteed on every path -- no need to check more
        if free_id in alloc_reach and sink_id in _reachable_from(succ, free_id):
            status = 'AMBIGUOUS'   # possible on some path; keep checking others
    return status


def compute_allocation_extents(d):
    """Returns {(function_id, pointer_name): AllocationExtentFact} for every pointer
    this module can establish a fact for, across the whole file -- WITHOUT free
    reasoning, which is now CFG-sensitive and per-sink (see
    `capacity_status_at_sink`), not a property of the extent fact itself. AMBIGUOUS
    (conflicting direct allocations) keys are simply absent (never returned), same
    "abstain rather than guess" posture as everywhere else in this family."""
    calls = d.get('calls', [])
    functions = d.get('functions', [])
    assign_calls = [c for c in calls if c.get('name') == '<operator>.assignment']

    # --- direct allocations -------------------------------------------------
    direct = {}       # (fn, ptr) -> fact
    conflicted = set()

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
