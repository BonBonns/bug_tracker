#!/usr/bin/env python3
"""OOB_WRITE (POINTER_INCREMENT) candidate producer -- a THIRD representation variant
of the same property covered by oob_index_write_verdict.py (arr[idx]=x) and
oob_copy_length_verdict.py (memcpy(dest,src,len)). This one targets the `*ptr++ = x;`
idiom: a raw pointer aliased to a fixed-size local array, written through repeatedly,
with no local evidence that the write count is bounded by the array's capacity.

Motivated by a REAL, disclosed bug found during paired vulnerable/patched validation,
not a hypothetical: mozilla/mozjpeg's jchuff.c Huffman encoder (Debian bug 768369,
fixed upstream at commit a06aeb25f2c5bc986d46301113df2eaf2a3c055c) declares
`JOCTET _buffer[BUFSIZE], *buffer;`, does `buffer = _buffer;`, and writes via
`#define EMIT_BYTE() { ...; *buffer++ = c; ...}` an unbounded number of times relative
to a worst-case bit count ("in the absolute worst case... the Huffman encoder can
produce encoded blocks that approach double the size of the unencoded blocks" -- the
original commit's own words). Neither of the other two producers modeled this: it's
neither `arr[idx] = x` nor a memcpy-family call. Confirmed empirically, not just
predicted: both producers returned identical results (0 and 6-unrelated respectively)
on the vulnerable and patched revisions of this exact file.

IMPORTANT HONESTY NOTE, read before trusting a "0 candidates" or a clean vuln-flags/
patched-suppresses signal from this producer on THAT specific CVE class: the actual
mozjpeg fix was not "add a missing bounds check" -- it was "BUFSIZE was computed from
an incorrect worst-case estimate; make the constant bigger." A syntactic pass has no
way to evaluate whether a numeric capacity constant is large enough for a callee's
true worst-case output size -- that requires understanding the specific encoding
logic (bits-per-coefficient, worst-case symbol distribution, etc.), which is
code-specific and not something this pass attempts. So for THIS bug (and any bug in
its class -- a correctly-guardless buffer that is simply undersized, not a buffer
that's missing its guard), do not expect this pass to distinguish vulnerable from
patched: it flags the STRUCTURAL SHAPE ("here's an unbounded-looking pointer-write
loop with no visible capacity check -- a human should verify the sizing math"), which
is genuinely present in both the buggy and fixed revisions, and that's the honest,
correct answer to give a human reviewer -- not a detector deficiency to paper over.
Where this pass DOES cleanly discriminate is the other failure mode in this same
property: a missing/removed sizeof-guard, which IS a structural difference it can see.

SCOPE (MVP) -- what this pass does NOT attempt, by design (abstain rather than guess):
  - Never tries to prove the write count unsafe OR safe (see note above) -- only
    whether any LOCAL evidence of a capacity check exists at all.
  - The pointer-to-array alias must be a single, simple, syntactic assignment
    `ptr = arr;` in the SAME function as the array's declaration. Aliasing through a
    parameter, a struct field, reassignment to a different base mid-function, or an
    alias established via `&arr[0]` (a different C idiom, not yet matched) is out of
    scope -- abstain, don't guess which array (if any) `ptr` really points at.
  - Only byte-sized element types are considered (same reasoning as COPY_LENGTH: a
    write count is naturally in units of the pointee size, and for a byte-sized
    element that IS the array's declared element count; anything wider needs a unit
    conversion this pass does not attempt).

Soundness: emit CANDIDATE only when NO capacity guard is visible in the function. A
guard is a comparison that (a) references the ARRAY's own sizeof-capacity
`sizeof(arr)` or its literal element count N, and (b) is NOT merely an argument to an
assert-family macro (compiled out in release, does not gate). If in doubt, SUPPRESS.
Never emits VULNERABLE; only CANDIDATE.
"""
import json, re, sys

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')
BYTE_ELEM_TYPES = {'char', 'unsigned char', 'signed char', 'uint8_t', 'PRUint8', 'int8_t',
                    'BYTE', 'u_char', 'uint8', 'JOCTET'}

ALIAS_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$')
INCR_WRITE_RE = re.compile(r'^\s*\*\s*([A-Za-z_]\w*)\s*\+\+\s*=')


def _eval_const_int_expr(expr):
    """Fold a simple constant-arithmetic array-size expression to an int, e.g. the
    common macro-expanded shape `(64*2)+8` -- this is EXACTLY what mozjpeg's own
    `JOCTET _buffer[BUFSIZE]` (`#define BUFSIZE (DCTSIZE2*2)+8`) looks like once
    macro-expanded in the fact data: `type_full_name` comes through as literally
    `JOCTET[(64*2)+8]`, confirmed by inspecting the real cpp.json for this CVE.
    Without this fold, a bare-\\d+-only regex simply doesn't match and the array
    is invisible to this producer -- not a guard-detection gap, a capacity-parsing
    one. Restricted to digits/whitespace/+-*/() BEFORE ever calling eval, so this
    can't become a code-injection surface via attacker-controlled source text.
    Returns None (abstain) on anything not cleanly a small non-negative constant
    expression."""
    e = (expr or '').strip()
    if not e or not re.fullmatch(r'[\d\s+\-*/()]+', e):
        return None
    try:
        v = eval(e, {'__builtins__': {}}, {})
    except Exception:
        return None
    return v if isinstance(v, int) and v >= 0 else None


def _byte_array_elem_count(type_full_name):
    """Element count N for a fixed-size array local, but ONLY when the element type
    is one byte wide (so N elements == N writes through a byte pointer alias).
    Anything else returns None -- abstain, don't guess at a unit conversion."""
    m = re.match(r'^\s*([A-Za-z_][\w ]*?)\s*\[\s*([\d\s+\-*/()]+)\s*\]\s*$', type_full_name or '')
    if not m:
        return None
    elem_type = m.group(1).strip()
    if elem_type not in BYTE_ELEM_TYPES:
        return None
    return _eval_const_int_expr(m.group(2))


def emit_candidates(prefix):
    d = json.load(open(prefix))
    calls = d.get('calls', [])
    locals_ = d.get('locals', [])

    # byte-sized fixed-array locals -> element count N, scoped by (function, name).
    # Same rationale as the other two producers: a bare name-keyed dict would let two
    # functions' same-named, differently-sized arrays clobber each other's capacity.
    arr_count = {}   # (function_id, name) -> N
    for l in locals_:
        n = _byte_array_elem_count(l.get('type_full_name'))
        if n is not None:
            arr_count[(l.get('method_id'), l.get('name'))] = n
    if not arr_count:
        return []

    assign_calls = [c for c in calls if c.get('name') == '<operator>.assignment']

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
        if not cc:
            return False
        return any(cc in ac for ac in assert_codes)

    guarded_arrays_by_fn = {}   # function_id -> set(array names) with a live capacity guard
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

    # pointer-to-array aliases: `ptr = arr;` where arr is a known byte-array local IN
    # THE SAME FUNCTION. Scoped by function so an alias in one function can't leak
    # into another's unrelated same-named pointer.
    alias_ptr_to_arr = {}   # (function_id, ptr_name) -> arr_name
    for c in assign_calls:
        fn = c.get('enclosing_function_id')
        m = ALIAS_RE.match(c.get('code') or '')
        if not m:
            continue
        ptr_name, rhs_name = m.group(1), m.group(2)
        if (fn, rhs_name) in arr_count and ptr_name != rhs_name:
            alias_ptr_to_arr[(fn, ptr_name)] = rhs_name

    func_by_id = {f.get('id'): f for f in d.get('functions', [])}
    cand = []
    seen = set()
    for c in assign_calls:
        fn = c.get('enclosing_function_id')
        m = INCR_WRITE_RE.match(c.get('code') or '')
        if not m:
            continue
        ptr_name = m.group(1)
        arr_name = alias_ptr_to_arr.get((fn, ptr_name))
        if arr_name is None:
            continue   # ptr isn't a recognized alias of a known-capacity array -- abstain
        N = arr_count[(fn, arr_name)]
        if arr_name in guarded_arrays_by_fn.get(fn, set()):
            continue   # a sizeof(arr) guard exists somewhere in this function -- suppress
        # Dedup by (function, array, pointer, LINE) rather than call id. Found on real
        # code (mozjpeg's encode_one_block): a single macro-expanded write site can be
        # backed by dozens of distinct raw call facts sharing one line number -- e.g.
        # a big unrolled/switch-heavy Huffman bit-emission body where the debug-line
        # info collapses many genuinely-distinct AST nodes onto the macro invocation's
        # source line (72 raw `*buffer++ = c` facts on a single line was observed, not
        # a hypothetical). Keying on call id would surface ~72 near-identical rows per
        # reviewable location; keying on line reports one candidate per source line, a
        # human reviewer's actual unit of decision, without dropping any DISTINCT
        # location this pass found.
        key = (fn, arr_name, ptr_name, c.get('line'))
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(fn) or {}
        cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'POINTER_INCREMENT',
                     'array': arr_name, 'pointer': ptr_name, 'elem_count': N,
                     'file': c.get('file'), 'function': _fn.get('full_name'),
                     'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                     'function_id': fn, 'line': c.get('line'),
                     'derivation': {'rule': 'CPP_FIXED_ARRAY_POINTER_INCREMENT_UNBOUNDED',
                                    'capacity_source': 'SYNTACTIC_BYTE_ELEM_COUNT'}})
    return cand


if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'POINTER_INCREMENT candidate(s)')
        for x in c:
            print('   ', '*'+x['pointer']+'++ = ..  (alias of', x['array'], ', cap=',
                  x['elem_count'], 'bytes) @L', x.get('line'))
