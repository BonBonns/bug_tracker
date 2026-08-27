#!/usr/bin/env python3
"""OOB-RUNTIMECAP-R01 gate. Validates allocation_extent.py's AllocationExtentFact
propagation (consumed by oob_runtime_capacity_verdict.py) against the full
conservative-handling matrix: literal and symbolic malloc, a real guard on a
symbolic capacity, literal calloc, symbolic-multiplication calloc (must NOT
establish a capacity), realloc REPLACING a prior extent, free() INVALIDATING an
extent, two conflicting direct allocations producing AMBIGUOUS (no fact, not a
guess), alias propagation, pointer-plus-offset derivation, single-hop
interprocedural propagation, and an unknown/uncontracted allocator (must remain
UNRESOLVED, not guessed at)."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
TOOLS = H.parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("orc", TOOLS / "oob_runtime_capacity_verdict.py")
orc = importlib.util.module_from_spec(spec); spec.loader.exec_module(orc)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

c = orc.emit_candidates(str(H / "fixtures" / "controls.program.json"))
by_fn = {x['function_id']: x for x in c}

ck("exactly 10 candidates (literal-malloc, symbolic-malloc, calloc-literal, alias, "
   "offset, interproc, plus the 4 additive-safety controls below -- only the "
   "exact-match case is excluded)",
   len(c) == 10)

ck("vuln_literal_malloc FLAGGED, capacity=64 (literal malloc)",
   970000000001 in by_fn and by_fn[970000000001]['extent_in_bytes'] == 64)

ck("vuln_symbolic_malloc FLAGGED, capacity expression 'n' (symbolic, no literal fold)",
   970000000002 in by_fn and by_fn[970000000002]['size_expression'] == 'n'
   and by_fn[970000000002]['extent_in_bytes'] is None)

ck("guarded_symbolic suppressed (len > n directly relates width to the symbolic capacity)",
   970000000003 not in by_fn)

ck("vuln_calloc_literal FLAGGED, capacity=64 (calloc(4,16), both literal)",
   970000000004 in by_fn and by_fn[970000000004]['extent_in_bytes'] == 64)

ck("abstain_calloc_symbolic ABSTAINED (calloc(count,16), count symbolic -- "
   "multiplication overflow not ruled out, never established)",
   970000000005 not in by_fn)

ck("vuln_realloc_replaces NOT flagged (realloc(p,64) REPLACES the prior malloc(8) "
   "extent; write width 50 fits the NEW capacity 64, proving replacement happened -- "
   "if the old cap 8 had wrongly persisted, 50>8 would have flagged)",
   970000000006 not in by_fn)

ck("abstain_freed ABSTAINED (free(p) invalidates p's extent for the rest of the function)",
   970000000007 not in by_fn)

ck("abstain_conflict ABSTAINED (two DIFFERENT direct allocations to p, sizes 8 and "
   "16 -- ambiguous, no capacity guessed)",
   970000000008 not in by_fn)

ck("vuln_alias FLAGGED via q=p alias, capacity=64 inherited from p's own malloc(64)",
   970000000009 in by_fn and by_fn[970000000009]['dest'] == 'q' and by_fn[970000000009]['extent_in_bytes'] == 64)

ck("vuln_offset FLAGGED via q=p+16, effective capacity=64-16=48 (both literal); "
   "write width 100 exceeds it",
   970000000010 in by_fn and by_fn[970000000010]['extent_in_bytes'] == 48)

ck("helper_interproc FLAGGED via single-hop propagation of caller_interproc's "
   "malloc(64), capacity=64",
   970000000012 in by_fn and by_fn[970000000012]['extent_in_bytes'] == 64)

ck("abstain_unknown_allocator ABSTAINED (my_custom_alloc has no entry in "
   "ALLOCATOR_CONTRACTS -- unresolved structurally, not guessed at)",
   970000000013 not in by_fn)

# Real false positive found testing against NSS rsapkcs.c before this check existed:
# `tmpOutput = PORT_Alloc(inputLen); PORT_Memcpy(tmpOutput, in, inputLen);` --
# allocated and copied are the textually IDENTICAL expression, safe by construction.
ck("safe_exact_match suppressed (capacity expression == width expression, "
   "textually identical -- no guess needed)",
   970000000014 not in by_fn)

# SOUNDNESS CORRECTION (found post-hoc by external review, not by this session's
# own testing): an earlier version of this producer treated "the write width is
# one ADDEND of a `+`-only capacity sum" as automatically safe. That is NOT
# generally sound in C -- unsigned `x + y` can WRAP to something SMALLER than
# `x` (if `y` is large/attacker-influenced/unchecked), so `capacity = x + y;
# memcpy(p, src, x)` is exactly the shape this producer exists to catch, not a
# safe pattern. The additive-term rule has been REMOVED entirely (see the
# module's own comment at the removal site); only an EXACT-expression match
# remains an automatic safety rule, since that involves no arithmetic
# reasoning at all (x <= x, trivially true regardless of overflow/sign/units).
# The four cases below are the corrected control matrix: all must now FLAG,
# not silently suppress.

ck("vuln_additive_no_overflow_proof FLAGGED (buffer_len = SharedSecret->len + 4 "
   "+ SharedInfoLen, an UNCHECKED caller-supplied length; the write uses "
   "SharedSecret->len -- one addend of an unproven sum is NOT safe, no "
   "nonnegativity/overflow evidence exists for this pass to use)",
   970000000015 in by_fn)

ck("vuln_wraparound_shape FLAGGED (cap = SIZE_MAX + 2, then copy(p, SIZE_MAX) -- "
   "the additive-term rule this replaces would have WRONGLY suppressed this "
   "exact wraparound shape, since SIZE_MAX is textually 'one addend' of "
   "'SIZE_MAX + 2'; this is the concrete case proving the old rule unsound)",
   970000000016 in by_fn)

ck("vuln_unknown_sum FLAGGED (cap = x + y; copy(p, x) -- both symbolic, no "
   "evidence either addend is safe)",
   970000000017 in by_fn)

ck("vuln_signed_negative_term FLAGGED (cap = x + adjustment; copy(p, x) -- "
   "adjustment is a signed int and could be negative, making the sum smaller "
   "than x)",
   970000000018 in by_fn)

print(f"OOB_RUNTIMECAP_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
