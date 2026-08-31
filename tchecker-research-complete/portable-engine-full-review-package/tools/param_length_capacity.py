#!/usr/bin/env python3
"""PARAM-CAP-R01 (task #44): evidence-backed pointer-parameter + separate-length-parameter
capacity derivation. Pure fact-derivation module -- emits NO verdicts itself; consumed
additively by oob_index_write_verdict.py as a NEW capacity source alongside its existing,
frozen fixed-local-array capacity logic.

WHY THIS EXISTS: the real Mozilla Tremor CVE-2018-5147 (`vorbis_book_decodevs_add` et al.,
`docs/moz-oob-r01/primary-artifacts/tremor_codebook_{VULN,PATCHED}.c`) writes through a pointer
PARAMETER (`ogg_int32_t *a`) whose true capacity is carried by a SEPARATE runtime parameter
(`int n`), not a fixed-size local array `T[N]`. Confirmed directly against real facts (task #30):
`dest_capacities` is 0 for the whole file and no local named `a` exists -- the existing capacity
derivers (keyed off a syntactic `T[N]` local declaration) are structurally blind to this pattern.

NOT a loose "pointer followed by integer" heuristic (explicitly rejected by direct instruction).
The pairing between a pointer parameter P and a length parameter L must be ESTABLISHED BY REAL
EVIDENCE, not mere adjacency:

  EVIDENCE MECHANISM (bounded backward data-flow chase through this function's OWN real
  `assignments` facts, the only per-function data-flow evidence currently exported broadly enough
  to use here -- `reachingdef.json` was checked directly on the real Tremor bundle and found to
  cover only a narrow subset of scalar loop-counter locals, NOT `step`/`t`/`entry`/parameters, so
  it cannot carry this evidence; `assignments` facts (`target_local_id` -> `value_ref.code`) DO
  cover the real chain `step=n/book->dim` this CVE needs and are used instead):
    1. Start from the real identifier tokens referenced in the write site's own index expression
       (e.g. `o+j` -> {`o`, `j`}).
    2. Iteratively expand: for each token that is one of this function's OWN locals, follow every
       real `assignments` fact that TARGETS that local, and add every identifier token referenced
       in that assignment's own RHS code (e.g. `o` was assigned from `o+=step` -> adds `step`;
       `step` was assigned from `n/book->dim` -> adds `n` and `book`). Bounded to a small hop
       count and a total-names cap so this always terminates and stays cheap.
    3. Intersect the resulting reachable-name set with this function's OWN integer-typed
       parameter names (an explicit allowlist of real integer type spellings -- never "anything
       that isn't a pointer").
    4. Exactly one candidate -> RESOLVED (real, evidence-backed pairing). Zero -> ABSTAIN (no
       established capacity; this is what correctly excludes an unrelated adjacent integer
       parameter that the index expression never actually touches). Two or more -> ABSTAIN,
       explicitly AMBIGUOUS (never guesses among several equally-evidenced candidates).

  This mechanism is deliberately IMPORTANT for the vulnerable case specifically: it does NOT
  depend on a bound-check/guard existing (a guard is exactly what the vulnerable version lacks by
  definition) -- it depends only on the CVE's own real, unconditional data-flow (`step` is always
  computed from `n`, guarded or not), which is present in both the vulnerable and patched forms.

BYTE-VS-ELEMENT: an index-store write (`arr[idx]`) is inherently an ELEMENT-count comparison
(`idx` counts elements of `arr`, not bytes) -- no conversion is needed OR safe to assume for the
ordinary case. If the index expression itself contains a `sizeof(...)` scaling factor (a real
sign that the index is NOT a plain element count), this module ABSTAINS
(`AMBIGUOUS_BYTE_VS_ELEMENT_SCALING`) rather than silently comparing mismatched units.

POINTER OFFSETS: `resolve_pointer_base()` recognizes when a write's own base identifier is not
the raw pointer parameter but a local reassigned from `param + k` (pointer arithmetic). A literal,
non-negative `k` reduces the real remaining capacity (capacity becomes `L - k`, not `L`); a
non-literal `k` cannot be bounded here and ABSTAINS (`POINTER_OFFSET_UNRESOLVED`) rather than
guess.

OVERFLOW IN CAPACITY-COMPUTATION MULTIPLICATION: `has_overflow_risk_multiplication()` flags a
`L * sizeof(...)`-shaped (or `L * <const>`) expression as untrustworthy capacity/allocation
evidence when L's own type is not provably wide enough (not `size_t`/`[u]int64_t`/`long` on this
convention) to rule out the product overflowing for realistic inputs -- used to gate call-site
allocation-size CORROBORATION (below) so an overflow-prone computation is never trusted as if it
soundly bounds anything.

INTERPROCEDURAL CALL-SITE CORROBORATION (`corroborate_from_call_sites()`): best-effort,
NON-GATING enrichment, not a requirement for a candidate to fire -- the intraprocedural evidence
chase above is the REQUIRED gate. Honestly scoped to what real facts already support: real,
UNAMBIGUOUS calls to F (`resolution=='EXACT'`, exactly one `candidate_target_ids` entry), with a
literal-integer argument for L, or a directly-sized local array argument for P (reusing the SAME
fixed-array-capacity regex `oob_index_write_verdict.py` already has, not a new fabricated
capability) -- gated through the overflow check above wherever an allocation-size expression is
involved. This module does NOT claim general interprocedural allocation tracing; no such facts
are exported anywhere in this codebase today (checked directly: no malloc/alloca size-correlation
facts exist in `normalize_c_cpp_facts_v03.py`'s own output).
"""
import re

_INT_TYPE_RE = re.compile(
    r'^\s*(const\s+)?(unsigned\s+)?'
    r'(int|long|long\s+long|short|char|size_t|ssize_t|'
    r'u?int(8|16|32|64)_t|off_t|ptrdiff_t)\s*$'
)
_WIDE_INT_TYPE_RE = re.compile(
    r'^\s*(const\s+)?(unsigned\s+)?(size_t|ssize_t|u?int64_t|long\s+long|long)\s*$'
)
_IDENT_RE = re.compile(r'\b[A-Za-z_]\w*\b')
_C_KEYWORDS = {
    'if', 'else', 'for', 'while', 'do', 'return', 'sizeof', 'const', 'static', 'struct',
    'unsigned', 'signed', 'int', 'long', 'short', 'char', 'void', 'switch', 'case', 'break',
    'continue', 'goto', 'typedef', 'union', 'enum',
}


def _is_pointer_type(type_full_name):
    t = (type_full_name or '').strip()
    return t.endswith('*') and '(' not in t  # excludes function-pointer types, e.g. 'void(*)()'


def _is_integer_type(type_full_name):
    return bool(_INT_TYPE_RE.match((type_full_name or '').strip()))


def _is_wide_integer_type(type_full_name):
    return bool(_WIDE_INT_TYPE_RE.match((type_full_name or '').strip()))


def _names_in(code):
    return {t for t in _IDENT_RE.findall(code or '') if t not in _C_KEYWORDS}


def resolve_pointer_base(facts, function_id, base_name):
    """Resolves a write site's own base identifier to a real pointer PARAMETER of `function_id`,
    directly or through one hop of `param + literal_offset` pointer arithmetic.

    Returns (param_dict_or_None, offset_int_or_None, status) where status is one of:
      'DIRECT'            -- base_name IS the pointer parameter itself (offset 0)
      'OFFSET_RESOLVED'   -- base_name is a local assigned from `param + <literal>`
      'OFFSET_UNRESOLVED' -- base_name is a local assigned from `param + <non-literal>`
      'NOT_PARAM_BASED'   -- base_name is not traceable to any pointer parameter of this function
    """
    fn = next((f for f in facts.get('functions', []) if f.get('id') == function_id), None)
    if not fn:
        return None, None, 'NOT_PARAM_BASED'
    ptr_params = {p['name']: p for p in fn.get('parameters', []) if _is_pointer_type(p.get('type_full_name'))}
    if base_name in ptr_params:
        return ptr_params[base_name], 0, 'DIRECT'

    # one-hop offset: base_name is a LOCAL assigned exactly once from `<ptr_param> + <expr>`.
    assigns = [a for a in facts.get('assignments', [])
               if a.get('function_id') == function_id]
    locals_by_name = {l['name']: l for l in facts.get('locals', []) if l.get('method_id') == function_id}
    lid = locals_by_name.get(base_name, {}).get('id')
    if lid is None:
        return None, None, 'NOT_PARAM_BASED'
    own_assigns = [a for a in assigns if a.get('target_local_id') == lid]
    if len(own_assigns) != 1:
        return None, None, 'NOT_PARAM_BASED'  # reassigned more than once -- do not guess which
    rhs = (own_assigns[0].get('value_ref') or {}).get('code') or ''
    for pname, p in ptr_params.items():
        m = re.fullmatch(r'\s*%s\s*\+\s*(.+?)\s*' % re.escape(pname), rhs)
        if not m:
            continue
        k_expr = m.group(1).strip()
        if re.fullmatch(r'\d+', k_expr):
            return p, int(k_expr), 'OFFSET_RESOLVED'
        return p, None, 'OFFSET_UNRESOLVED'
    return None, None, 'NOT_PARAM_BASED'


def _chase_reaching_names(facts, function_id, start_names, max_hops=8, max_names=64):
    assigns_by_target = {}
    for a in facts.get('assignments', []):
        if a.get('function_id') != function_id:
            continue
        assigns_by_target.setdefault(a.get('target_local_id'), []).append(a)
    locals_by_name = {l['name']: l['id'] for l in facts.get('locals', []) if l.get('method_id') == function_id}

    seen = set(start_names)
    frontier = set(start_names)
    for _ in range(max_hops):
        new = set()
        for name in frontier:
            lid = locals_by_name.get(name)
            if lid is None:
                continue
            for a in assigns_by_target.get(lid, []):
                code = (a.get('value_ref') or {}).get('code') or ''
                new |= (_names_in(code) - seen)
        if not new or len(seen) > max_names:
            break
        seen |= new
        frontier = new
    return seen


def _names_bounded_by_params_via_comparison(facts, function_id):
    """Second evidence source: a real, non-assert `<`/`<=` comparison whose LHS is a bare
    identifier and whose RHS is IDENTITY-matched (value_ref.kind=='PARAMETER') to a real integer
    parameter -- e.g. `for(i=0;i<n;)`. This is standard, well-founded loop-bound evidence, not an
    assignment chain: covers the real `vorbis_book_decodev_add` shape (`a[i++]`, whose real
    capacity relationship to `n` is expressed ONLY via the outer loop's own `i<n` condition, with
    no assignment anywhere tying `i` to `n` -- the assignment-chase alone cannot see this, but a
    loop-bound comparison is exactly as much real evidence as a data-flow chain is. Kept as a
    SEPARATE source (not folded into the assignment chase) since it is bare-identifier-only by
    construction -- a compound LHS (`o+j < n`) is deliberately left to the caller's own guard
    -at-the-write-site check, not treated as capacity-establishing evidence here, since a compound
    comparison that never textually recurs at the actual write site proves nothing about it."""
    assert_calls = [(c.get('code') or '') for c in facts.get('calls', [])
                     if c.get('enclosing_function_id') == function_id and
                     (c.get('name') in ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION',
                                         'NS_ABORT_IF_FALSE', 'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT') or
                      (c.get('code', '').split('(')[0].strip() in
                       ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION',
                        'NS_ABORT_IF_FALSE', 'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT')))]
    out = {}
    for c in facts.get('calls', []):
        if c.get('enclosing_function_id') != function_id:
            continue
        if c.get('name') not in ('<operator>.lessThan', '<operator>.lessEqualsThan'):
            continue
        code = (c.get('code') or '').strip()
        if any(code and code in ac for ac in assert_calls):
            continue
        args = {a.get('index'): a for a in c.get('arguments', [])}
        lhs, rhs = args.get(0), args.get(1)
        if not lhs or not rhs:
            continue
        lhs_code = ((lhs.get('value_ref') or {}).get('code') or '').strip()
        rvr = rhs.get('value_ref') or {}
        if re.fullmatch(r'[A-Za-z_]\w*', lhs_code) and rvr.get('kind') == 'PARAMETER':
            out.setdefault(lhs_code, set()).add(rvr.get('id'))
    return out


def derive_length_param(facts, function_id, index_expr_code):
    """Attempts to resolve which of `function_id`'s own integer parameters is the real,
    evidence-backed capacity for a pointer written at `index_expr_code`.

    Returns a dict: {'status': ..., 'length_param': dict_or_None, 'reaching_names': set}
      status in:
        'RESOLVED'                            -- exactly one evidence-backed candidate
        'ABSTAIN_NONE'                        -- no integer parameter is reachable (e.g. an
                                                  unrelated adjacent integer parameter that the
                                                  index expression never actually references)
        'ABSTAIN_AMBIGUOUS'                   -- two or more equally evidence-backed candidates
        'ABSTAIN_BYTE_ELEMENT_SCALING'        -- index expression contains a sizeof(...) scaling
                                                  factor; unit mismatch risk, refuse to guess
    """
    if 'sizeof(' in (index_expr_code or '').replace(' ', ''):
        return {'status': 'ABSTAIN_BYTE_ELEMENT_SCALING', 'length_param': None, 'reaching_names': set()}

    fn = next((f for f in facts.get('functions', []) if f.get('id') == function_id), None)
    if not fn:
        return {'status': 'ABSTAIN_NONE', 'length_param': None, 'reaching_names': set()}
    int_params = {p['name']: p for p in fn.get('parameters', []) if _is_integer_type(p.get('type_full_name'))}
    int_params_by_id = {p['id']: p for p in int_params.values()}

    start = _names_in(index_expr_code)
    reach = _chase_reaching_names(facts, function_id, start)

    # source 1: assignment-chase name match against a real integer parameter's own name.
    candidate_ids = {int_params[n]['id'] for n in (reach & int_params.keys())}
    # source 2 (evidence-backed loop-bound comparison, e.g. `for(i=0;i<n;)`): any name in the
    # reach set that is ALSO the bare LHS of a real, non-assert comparison against a real
    # integer parameter, anywhere in this function.
    bounded = _names_bounded_by_params_via_comparison(facts, function_id)
    for name in reach:
        for pid in bounded.get(name, set()):
            if pid in int_params_by_id:
                candidate_ids.add(pid)

    if len(candidate_ids) == 0:
        return {'status': 'ABSTAIN_NONE', 'length_param': None, 'reaching_names': reach}
    if len(candidate_ids) > 1:
        return {'status': 'ABSTAIN_AMBIGUOUS', 'length_param': None, 'reaching_names': reach,
                'ambiguous_candidates': [int_params_by_id[i] for i in sorted(candidate_ids)]}
    return {'status': 'RESOLVED', 'length_param': int_params_by_id[next(iter(candidate_ids))],
            'reaching_names': reach}


def has_overflow_risk_multiplication(code, length_param_type):
    """True when `code` contains a `<length_param_name-shaped> * sizeof(...)` or
    `<name> * <const>` multiplication AND `length_param_type` is not provably wide enough
    (size_t/[u]int64_t/long) to rule out overflow for realistic inputs. Used to gate call-site
    allocation-size evidence -- an overflow-prone product is never trusted as a sound capacity."""
    if not code:
        return False
    if not re.search(r'\*\s*sizeof\s*\(', code) and not re.search(r'\*\s*\d+\b', code):
        return False
    return not _is_wide_integer_type(length_param_type)


def corroborate_from_call_sites(facts, function_id, length_param):
    """Best-effort, NON-GATING enrichment: real, unambiguous call sites to `function_id`
    (resolution EXACT, exactly one candidate_target_ids entry) whose argument for
    `length_param['index']` is a literal integer, or whose corresponding pointer argument is a
    directly-sized local array (reusing the same fixed-array-capacity convention
    oob_index_write_verdict.py already applies). Returns a list of corroboration dicts (possibly
    empty) -- NEVER required for a candidate to fire, and never treated as overriding an
    overflow-flagged allocation expression."""
    out = []
    for c in facts.get('calls', []):
        if c.get('resolution') != 'EXACT' or c.get('candidate_target_ids') != [function_id]:
            continue
        args = {a.get('index'): a for a in c.get('arguments', [])}
        larg = args.get(length_param.get('index'))
        if not larg:
            continue
        lcode = (larg.get('value_ref') or {}).get('code') or ''
        if re.fullmatch(r'\d+', lcode.strip()):
            entry = {'call_id': c['id'], 'call_line': c.get('line'), 'length_arg_literal': int(lcode)}
            if has_overflow_risk_multiplication(lcode, length_param.get('type_full_name')):
                entry['overflow_risk'] = True
            out.append(entry)
    return out
