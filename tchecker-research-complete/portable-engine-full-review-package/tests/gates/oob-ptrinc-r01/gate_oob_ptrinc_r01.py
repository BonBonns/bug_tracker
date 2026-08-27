#!/usr/bin/env python3
"""OOB-PTRINC-R01 gate. Validates oob_pointer_increment_verdict.py -- the
pointer-increment (`*ptr++ = x`) representation variant of the OOB_WRITE rule --
against a synthetic control matrix covering: an unbounded pointer-increment write
through a recognized alias of a byte-sized fixed array (must flag), a sizeof-guard
on that same array (must suppress), an assert-only guard that does NOT count as a
live capacity check (must still flag), and two out-of-scope shapes that must
ABSTAIN rather than guess (no recognized alias at all; a non-byte-element array,
where the element-count-to-write-count relationship isn't 1:1 without a unit
conversion this pass deliberately does not attempt)."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "opi", H.parent.parent.parent / "tools" / "oob_pointer_increment_verdict.py")
opi = importlib.util.module_from_spec(spec); spec.loader.exec_module(opi)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

c = opi.emit_candidates(str(H / "fixtures" / "controls.program.json"))
by_fn = {x['function_id']: x for x in c}

ck("exactly 2 candidates (unbounded + assert-only-guard-doesn't-count)", len(c) == 2)
ck("vuln_unbounded FLAGGED: *buffer++ = c, alias of _buffer[8]", 920000000001 in by_fn
   and by_fn[920000000001]['array'] == '_buffer' and by_fn[920000000001]['pointer'] == 'buffer'
   and by_fn[920000000001]['elem_count'] == 8)
ck("guarded_sizeof suppressed (n > sizeof(_buffer) credited)", 920000000002 not in by_fn)
ck("out_of_scope_no_alias abstained (buffer never aliased to a known array)",
   920000000003 not in by_fn)
ck("out_of_scope_int_array abstained (non-byte element, no unit guess)",
   920000000004 not in by_fn)
ck("asserted_only_still_flags FLAGGED (MOZ_ASSERT-wrapped guard compiles out, doesn't gate)",
   920000000005 in by_fn and by_fn[920000000005]['array'] == '_buffer')

print(f"OOB_PTRINC_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
