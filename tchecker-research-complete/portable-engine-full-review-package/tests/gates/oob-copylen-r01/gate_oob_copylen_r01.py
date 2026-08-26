#!/usr/bin/env python3
"""OOB-COPYLEN-R01 gate. Validates oob_copy_length_verdict.py -- the memcpy-length
representation variant of the INDEX_STORE (array[idx]) OOB_WRITE rule -- against a
synthetic control matrix covering: an unbounded copy (must flag), a sizeof-guard
(must suppress), a literal-bound guard (must suppress), a provably-safe constant
length (must suppress), and two out-of-scope shapes that must ABSTAIN rather than
guess (a pointer destination with unknown capacity; a non-byte-element array, where
byte-length can't be compared to element-count without a unit conversion this pass
deliberately does not attempt)."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "ocl", H.parent.parent.parent / "tools" / "oob_copy_length_verdict.py")
ocl = importlib.util.module_from_spec(spec); spec.loader.exec_module(ocl)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

c = ocl.emit_candidates(str(H / "fixtures" / "controls.program.json"))
by_fn = {x['function_id']: x for x in c}

ck("exactly 1 candidate (only the unbounded copy)", len(c) == 1)
ck("vuln_unbounded FLAGGED: memcpy(buf,..,len) with buf cap=16", 910000000001 in by_fn
   and by_fn[910000000001]['dest'] == 'buf' and by_fn[910000000001]['elem_count'] == 16
   and by_fn[910000000001]['len_expr'] == 'len')
ck("guarded_sizeof suppressed (len > sizeof(buf) credited)", 910000000002 not in by_fn)
ck("guarded_literal suppressed (len < 16 credited)", 910000000003 not in by_fn)
ck("safe_const_len suppressed (8 <= 16, provably in bounds)", 910000000004 not in by_fn)
ck("out_of_scope_pointer abstained (dest capacity unknown, not guessed)", 910000000005 not in by_fn)
ck("out_of_scope_int_array abstained (non-byte element, no unit guess)", 910000000006 not in by_fn)
# Found scanning real mozilla/nss lib/ssl/sslsock.c (ssl_WriteV): a guard shaped
# `myIov.iov_len < first_len` was invisible to a bare-identifier-only match, so a
# genuinely-guarded copy was reported as a candidate. Field-access length
# expressions must be recognized too.
ck("guarded_field_access suppressed (io.iov_len < 16 credited, dotted name)", 910000000007 not in by_fn)

print(f"OOB_COPYLEN_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
