#!/usr/bin/env python3
"""FROZEN as of round 5 (moz-scan-paired-cve-validation-round1.md). Anchored by
tests/gates/moz-canon-r01, a canonical vulnerable/patched gate against real,
freshly-fetched mozjpeg source pinning this module's exact behavior on the one CVE it
was built for. Do not expand this module's write-sink vocabulary, alias-chaining, or
capacity resolution further without: (1) first re-running moz-canon-r01 to confirm
the change doesn't alter its pinned evidence (candidate count, recorded capacities,
structural shape) without an intentional, documented reason, and (2) recording the
change in that gate's evidence rather than silently drifting it. Sink generalization
beyond dereference syntax (call-argument sinks, e.g. HMAC_Finish) belongs in
oob_call_sink_verdict.py instead, per callee_contracts.py's independently-verified-
contract model -- NOT as an addition to this module's regex vocabulary.

OOB_WRITE (CURSOR) candidate producer -- generalizes oob_pointer_increment_verdict.py's
single fused `*ptr++ = x` pattern into a genuine CURSOR abstraction, per the expansion
order below (steps 1-5; step 6, cross-function/TU capacity propagation, is
deliberately NOT attempted here -- see module end).

MOTIVATION: `*buffer++ = c;` is really shorthand for an obligation this pass makes
explicit --
    write(base=buffer_0, offset=k, width=1)
    require: k + width <= capacity(buffer_0)
-- where `k` starts at 0 when `buffer` is aliased to `buffer_0` and grows by 1 (or by
`width`) each time the cursor advances, however the source code spells "advance":
fused into the write (`*p++ = x`), as a separate statement (`p++;`, `++p;`,
`p += n;`), or repeated across Duff's-device-style case-label fallthrough (many
`*to++ = *from++;` statements sharing one loop, each independently a write-then-
advance). The older producer only matched the first (fully fused) spelling; this one
recognizes all three write shapes and both increment spellings, and chains base-object
identity through pointer-to-pointer assignment (`q = p;`), not just pointer-to-array.

EXPANSION ORDER THIS MODULE IMPLEMENTS (steps 1-5 of 6; see step 6 below):
  1. Pointer-dereference WRITE sinks: `*p = x`, `*p++ = x`, `*(p + n) = x`. (Read
     sinks -- `x = *p` etc. -- are NOT modeled: this pass stays within the OOB_WRITE
     property this whole producer family covers; a symmetric OOB_READ pass would
     reuse this same cursor-tracking machinery but is out of scope here.)
  2. Base-object identity is preserved across `p = arr;` (pointer-to-array, as
     before) AND `q = p;` (pointer-to-pointer) chains, resolved to a fixed point so
     `to = buffer; from = to;` still resolves `from` back to `buffer`'s own array.
  3. Accumulated offset / width: NOT tracked as a precise symbolic value (see step 5
     -- conservative by design). What IS tracked: whether a cursor pointer has ANY
     advance evidence anywhere in its function (a fused write, a standalone
     increment, or `+= n`). A pointer with advance evidence is treated as capable of
     reaching an arbitrary, unbounded offset unless a capacity guard is visible --
     the same "flag unless guarded, never try to prove a tight bound" posture the
     other three producers in this family already use.
  4. Base-object capacity: STATIC (a fixed local byte array, same as the other
     producers) is fully supported. A narrow slice of RUNTIME capacity is also
     supported: `p = malloc(N);` / `p = PORT_Alloc(N);` / `p = PORT_ZAlloc(N);`
     where N folds to a literal constant (reuses the same charset-restricted
     `_eval_const_int_expr` evaluator as the other producers' macro-arithmetic
     array-size folding). A SYMBOLIC runtime size (`PORT_Alloc(modulusLen)`, as in
     NSS CVE-2019-17006/CVE-2021-43527) is explicitly NOT attempted -- that needs
     tracking a size expression across a call boundary or from a caller-supplied
     value, which is step 6's territory, not this pass's.
  5. Loop/iteration-count relationships to the final offset: modeled CONSERVATIVELY,
     meaning not modeled precisely at all -- see step 3. No attempt is made to prove
     a tight bound between a loop's trip count and the cursor's final offset; the
     only question this pass asks is "is there a visible guard on this array's
     capacity anywhere in the function," same whole-function-scoped guard-crediting
     design already used (and already documented as dominance-unaware) by
     oob_index_write_verdict.py, oob_copy_length_verdict.py, and
     oob_pointer_increment_verdict.py.
  6. NOT attempted here: extending capacity propagation across function and
     translation-unit boundaries (needed for the "ConvertImage"-style cross-file
     case, and for NSS CVE-2021-43527/CVE-2019-17006's true interprocedural gap).
     Deliberately last per the expansion order: steps 1-5 are scoped to plausibly
     recover CVE shapes where the cursor, its base object, and its capacity are all
     visible within one function (the mozjpeg case; NSS CVE-2019-11759's local-array
     case, MODULO its write going through a non-memcpy/non-deref sink this pass
     still can't see -- HMAC_Finish isn't a pointer-dereference write, it's an
     ordinary call, out of scope for a *dereference* sink pass by definition).

Soundness (same posture as the rest of this family): emit CANDIDATE only when a
recognized write sink, through a recognized cursor of a byte buffer with a resolvable
capacity, has NO visible non-assert capacity guard anywhere in its function. Abstain
(no candidate) on anything not matching the above -- an unrecognized advance form, an
unresolvable alias chain, a non-byte-element buffer, a symbolic allocation size.
Never emits VULNERABLE; only CANDIDATE.
"""
import json, re, sys

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')
BYTE_ELEM_TYPES = {'char', 'unsigned char', 'signed char', 'uint8_t', 'PRUint8', 'int8_t',
                    'BYTE', 'u_char', 'uint8', 'JOCTET'}
ALLOC_FUNCS = ('malloc', 'PORT_Alloc', 'PORT_ZAlloc')

ALIAS_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$')
ALLOC_RE = re.compile(
    r'^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(' + '|'.join(ALLOC_FUNCS) + r')\s*\(\s*([^()]+?)\s*\)\s*$')
INCR_WRITE_RE = re.compile(r'^\s*\*\s*([A-Za-z_]\w*)\s*\+\+\s*=(?!=)')          # *p++ = x
DEREF_WRITE_RE = re.compile(r'^\s*\*\s*([A-Za-z_]\w*)\s*=(?!=)')                # *p = x
OFFSET_DEREF_WRITE_RE = re.compile(r'^\s*\*\s*\(\s*([A-Za-z_]\w*)\s*\+\s*[^()]+?\s*\)\s*=(?!=)')  # *(p+n) = x
POSTINCR_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*\+\+\s*$')
PREINCR_RE = re.compile(r'^\s*\+\+\s*([A-Za-z_]\w*)\s*$')
COMPOUND_PLUS_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*\+=\s*.+$')


def _eval_const_int_expr(expr):
    """Same charset-restricted constant-arithmetic folder as the other producers
    (macro-expanded array/allocation sizes like `(64*2)+8` are common in real code;
    see oob_pointer_increment_verdict.py's module docstring for the original finding
    that motivated this). Digits/whitespace/+-*/() only, checked BEFORE eval()."""
    e = (expr or '').strip()
    if not e or not re.fullmatch(r'[\d\s+\-*/()]+', e):
        return None
    try:
        v = eval(e, {'__builtins__': {}}, {})
    except Exception:
        return None
    return v if isinstance(v, int) and v >= 0 else None


def _byte_array_elem_count(type_full_name):
    m = re.match(r'^\s*([A-Za-z_][\w ]*?)\s*\[\s*([\d\s+\-*/()]+)\s*\]\s*$', type_full_name or '')
    if not m:
        return None
    if m.group(1).strip() not in BYTE_ELEM_TYPES:
        return None
    return _eval_const_int_expr(m.group(2))


def emit_candidates(prefix):
    d = json.load(open(prefix))
    calls = d.get('calls', [])
    locals_ = d.get('locals', [])
    func_by_id = {f.get('id'): f for f in d.get('functions', [])}

    # STEP 4 (static half): byte-sized fixed-array locals -> element count N, scoped
    # by (function, name) -- same rationale as the rest of this producer family.
    arr_count = {}   # (function_id, name) -> N
    for l in locals_:
        n = _byte_array_elem_count(l.get('type_full_name'))
        if n is not None:
            arr_count[(l.get('method_id'), l.get('name'))] = n
    if not arr_count:
        # still worth continuing: a heap alloc alone (no fixed array in the file)
        # should still be reachable -- don't early-return here like the sibling
        # producers do, since arr_count isn't the only capacity source in this one.
        pass

    assign_calls = [c for c in calls if c.get('name') == '<operator>.assignment']

    # STEP 4 (runtime half, literal-only): `p = malloc(N)` / `PORT_Alloc(N)` /
    # `PORT_ZAlloc(N)` where N folds to a constant. A symbolic N (a parameter, a
    # field) is NOT resolved -- abstain, per the module docstring's step 4/6 split.
    for c in assign_calls:
        fn = c.get('enclosing_function_id')
        m = ALLOC_RE.match(c.get('code') or '')
        if not m:
            continue
        ptr_name, _func, size_expr = m.group(1), m.group(2), m.group(3)
        n = _eval_const_int_expr(size_expr)
        if n is not None:
            arr_count[(fn, ptr_name)] = n

    if not arr_count:
        return []

    def _cap_guard_arrays(code, fn):
        hits = set()
        for (mid, name) in arr_count:
            if mid == fn and ('sizeof(%s)' % name) in (code or ''):
                hits.add(name)
        return hits

    assert_codes = [(c.get('code') or '') for c in calls
                     if c.get('name') in ASSERT_NAMES
                     or (c.get('code', '').split('(')[0].strip() in ASSERT_NAMES)]

    def _in_assert(cmp_code):
        cc = (cmp_code or '').strip()
        return bool(cc) and any(cc in ac for ac in assert_codes)

    guarded_arrays_by_fn = {}   # function_id -> set(array/alloc names) with a live capacity guard
    for c in calls:
        if c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        if _in_assert(code):
            continue
        fn = c.get('enclosing_function_id')
        arrs = _cap_guard_arrays(code, fn)
        if arrs:
            guarded_arrays_by_fn.setdefault(fn, set()).update(arrs)

    # STEP 2: base-object identity, chained through pointer-to-pointer assignment.
    # Fixed-point resolution (a small, bounded number of passes -- function-local
    # alias chains are short in practice) so `to = buffer; from = to;` resolves
    # `from` all the way back to `buffer`'s own array/alloc, not just one hop.
    alias_ptr_to_base = {}   # (function_id, ptr_name) -> base_name (a key in arr_count)
    raw_aliases = []         # (fn, lhs, rhs) for every simple `lhs = rhs;` assignment
    for c in assign_calls:
        m = ALIAS_RE.match(c.get('code') or '')
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        if lhs != rhs:
            raw_aliases.append((c.get('enclosing_function_id'), lhs, rhs))
    for _ in range(4):   # bounded fixed point -- 4 hops is generous for real code
        changed = False
        for fn, lhs, rhs in raw_aliases:
            base = None
            if (fn, rhs) in arr_count:
                base = rhs
            elif (fn, rhs) in alias_ptr_to_base:
                base = alias_ptr_to_base[(fn, rhs)]
            if base is not None and alias_ptr_to_base.get((fn, lhs)) != base:
                alias_ptr_to_base[(fn, lhs)] = base
                changed = True
        if not changed:
            break

    # STEP 3 (advance evidence only, not a symbolic offset -- see module docstring):
    # which (function, pointer) pairs have ANY evidence of advancing, from any of
    # the three spellings: fused into a write, a standalone increment, or `+= n`.
    advanced_by_fn = {}   # function_id -> set(pointer names with advance evidence)
    for c in assign_calls:
        fn = c.get('enclosing_function_id')
        code = c.get('code') or ''
        m = INCR_WRITE_RE.match(code)
        if m:
            advanced_by_fn.setdefault(fn, set()).add(m.group(1))
    for c in calls:
        # `p += n` is its OWN operator (`<operator>.assignmentPlus`), not
        # `<operator>.assignment` -- must be read from the full `calls` list, not
        # `assign_calls`, or it's silently invisible as advance evidence.
        if c.get('name') != '<operator>.assignmentPlus':
            continue
        fn = c.get('enclosing_function_id')
        m = COMPOUND_PLUS_RE.match(c.get('code') or '')
        if m and ((fn, m.group(1)) in alias_ptr_to_base or (fn, m.group(1)) in arr_count):
            advanced_by_fn.setdefault(fn, set()).add(m.group(1))
    for c in calls:
        if c.get('name') not in ('<operator>.postIncrement', '<operator>.preIncrement'):
            continue
        fn = c.get('enclosing_function_id')
        code = c.get('code') or ''
        m = POSTINCR_RE.match(code) or PREINCR_RE.match(code)
        if m:
            advanced_by_fn.setdefault(fn, set()).add(m.group(1))

    # STEP 1: the three write-sink shapes, all read from the SAME `<operator>.assignment`
    # call family (Joern represents `*p = x`, `*p++ = x`, and `*(p+n) = x` this way).
    cand = []
    seen = set()
    for c in assign_calls:
        fn = c.get('enclosing_function_id')
        code = c.get('code') or ''
        m = INCR_WRITE_RE.match(code)
        shape = 'FUSED_INCREMENT'
        if not m:
            m = OFFSET_DEREF_WRITE_RE.match(code)
            shape = 'OFFSET_DEREF'
        if not m:
            m = DEREF_WRITE_RE.match(code)
            shape = 'PLAIN_DEREF'
        if not m:
            continue
        ptr_name = m.group(1)
        # A cursor's base is usually reached via an alias chain (`p = arr;` / `q = p;`
        # -> alias_ptr_to_base), but a literal-sized heap allocation (`p = malloc(64);`)
        # makes `p` ITSELF a capacity key in arr_count directly -- check that first.
        base = ptr_name if (fn, ptr_name) in arr_count else alias_ptr_to_base.get((fn, ptr_name))
        if base is None:
            continue   # ptr isn't a recognized cursor of a known-capacity base -- abstain
        # A write only through this cursor matters as a CURSOR write (vs. a single,
        # unrepeated dereference this pass has no evidence is unsafe) once there's
        # advance evidence for it somewhere in the function -- the fused shape IS
        # its own advance evidence; the other two shapes need separate evidence.
        if shape != 'FUSED_INCREMENT' and ptr_name not in advanced_by_fn.get(fn, set()):
            continue
        N = arr_count[(fn, base)]
        if base in guarded_arrays_by_fn.get(fn, set()):
            continue   # a sizeof(base) guard exists somewhere in this function -- suppress
        key = (fn, base, ptr_name, shape, c.get('line'))
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(fn) or {}
        cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'CURSOR',
                     'write_shape': shape, 'base': base, 'pointer': ptr_name, 'elem_count': N,
                     'file': c.get('file'), 'function': _fn.get('full_name'),
                     'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                     'function_id': fn, 'line': c.get('line'),
                     'derivation': {'rule': 'CPP_CURSOR_WRITE_UNBOUNDED',
                                    'capacity_source': 'SYNTACTIC_BYTE_ELEM_COUNT_OR_LITERAL_ALLOC'}})
    return cand


def analyze_operations(prefix):
    """Emit v1 analysis records for this producer's OPEN candidates. A cursor
    candidate is an unbounded pointer-increment write into a fixed-capacity base:
    the unresolved property is that the NUMBER of writes is not bounded by the
    capacity -- reason `write_count_bound_not_established` (relationship_unresolved,
    semantic_relationship_review). Abstention-reason emission (e.g.
    destination_identity_ambiguous for an unresolved alias chain) is a documented
    future extension; only explicit open-candidate reasons are emitted here, never
    a candidate-presence fallback."""
    import hashlib
    from analysis_record import (bucket_for_reason, route_for_reason,
                                 property_for_reason, llm_eligible_for_reason)
    reason = 'write_count_bound_not_established'
    recs = []
    for c in emit_candidates(prefix):
        rid = 'cand_' + hashlib.sha256(
            f"{c.get('function_id')}|{c.get('base')}|{c.get('line')}".encode()).hexdigest()[:16]
        recs.append({
            'candidate_id': rid, 'recognized_operation': 'cursor_write',
            'file': c.get('file'), 'function': c.get('function'), 'line': c.get('line'),
            'dest': c.get('base'), 'width_expr': None, 'analysis_status': 'open_candidate',
            'reason_code': reason, 'all_reason_codes': [reason],
            'uncertainty_bucket': bucket_for_reason(reason),
            'recommended_route': route_for_reason(reason),
            'unresolved_property': property_for_reason(reason),
            'llm_eligible': llm_eligible_for_reason(reason)})
    return recs


if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'CURSOR candidate(s)')
        for x in c:
            print('   ', x['write_shape'], 'through', x['pointer'], '(base', x['base'],
                  ', cap=', x['elem_count'], 'bytes) @L', x.get('line'))
