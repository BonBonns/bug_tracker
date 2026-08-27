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

ck("exactly 2 candidates (the unbounded copy + the unguarded offset copy)", len(c) == 2)
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
# Pointer-offset-destination extension, motivated by two real round-3 CVEs (NSS
# CVE-2016-1950's `item->data + item->len`, NSS CVE-2019-11759's
# `key_block + ((bi-1)*hashLen)`) -- narrow slice: a FIXED LOCAL byte-array plus an
# offset expression, offset/len both unbounded, no guard on the base array's capacity.
ck("offset_unguarded FLAGGED: memcpy(buf+off,..,len), buf cap=16, offset shape",
   910000000008 in by_fn and by_fn[910000000008]['dest'] == 'buf + off'
   and by_fn[910000000008]['array_base'] == 'buf' and by_fn[910000000008]['offset_shape'] is True
   and by_fn[910000000008]['elem_count'] == 16)
ck("offset_guarded suppressed (off + len > sizeof(buf) credited on base array)",
   910000000009 not in by_fn)
# Real false positive found scanning NSS pkcs11c.c with the extension above (before
# this check existed): `memcpy(newdeskey + 16, newdeskey, 8)` on a 24-byte
# newdeskey -- offset(16)+len(8)==24, exactly fits, a legitimate DES2->DES3 key
# extension, not a bug. Manually verified against the real source before fixing.
ck("offset_literal_safe_exact_fit suppressed (16+8==24, pure arithmetic, no guess)",
   910000000010 not in by_fn)

print(f"OOB_COPYLEN_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
