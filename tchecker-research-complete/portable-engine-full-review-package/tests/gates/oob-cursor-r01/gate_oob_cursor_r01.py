#!/usr/bin/env python3
"""OOB-CURSOR-R01 gate. Validates oob_cursor_write_verdict.py -- the cursor-based
generalization of the OOB_WRITE property covering `*p = x`, `*p++ = x`, and
`*(p + n) = x` write sinks, base-object identity chained through pointer-to-pointer
assignment, advance evidence from fused/standalone/compound-plus increments, and a
narrow literal-size heap-allocation capacity source alongside the usual fixed local
array -- against a synthetic control matrix. See the module docstring for the full
expansion-order rationale (steps 1-5; step 6, cross-function propagation, is out of
scope for this producer and this gate)."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "ocw", H.parent.parent.parent / "tools" / "oob_cursor_write_verdict.py")
ocw = importlib.util.module_from_spec(spec); spec.loader.exec_module(ocw)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

c = ocw.emit_candidates(str(H / "fixtures" / "controls.program.json"))
by_fn = {}
for x in c:
    by_fn.setdefault(x['function_id'], []).append(x)

ck("exactly 5 candidates (fused, plain-deref+advance, offset-deref+advance, chain-alias, heap-literal)",
   len(c) == 5)

ck("vuln_fused FLAGGED (FUSED_INCREMENT, base=buf, cap=8)",
   930000000001 in by_fn and by_fn[930000000001][0]['write_shape'] == 'FUSED_INCREMENT'
   and by_fn[930000000001][0]['base'] == 'buf' and by_fn[930000000001][0]['elem_count'] == 8)

ck("vuln_plain_deref_with_advance FLAGGED (PLAIN_DEREF, separate p++ is advance evidence)",
   930000000002 in by_fn and by_fn[930000000002][0]['write_shape'] == 'PLAIN_DEREF')

ck("vuln_offset_deref_with_advance FLAGGED (OFFSET_DEREF, separate p+=2 is advance evidence)",
   930000000003 in by_fn and by_fn[930000000003][0]['write_shape'] == 'OFFSET_DEREF')

ck("guarded_sizeof suppressed (n > sizeof(buf) credited)", 930000000004 not in by_fn)

ck("abstain_no_advance abstained (*p=c with no advance anywhere -- not a cursor write)",
   930000000005 not in by_fn)

ck("abstain_unrecognized_alias abstained (p never aliased to a known base)",
   930000000006 not in by_fn)

ck("chain_alias_flag FLAGGED via 2-hop chain (from -> to -> buffer)",
   930000000007 in by_fn and by_fn[930000000007][0]['base'] == 'buffer'
   and by_fn[930000000007][0]['pointer'] == 'from')

ck("heap_literal_flag FLAGGED (p = malloc(64), no local array at all, cap resolved from literal)",
   930000000008 in by_fn and by_fn[930000000008][0]['base'] == 'p'
   and by_fn[930000000008][0]['elem_count'] == 64)

ck("heap_symbolic_abstain abstained (malloc(n), n not a literal -- no capacity guess)",
   930000000009 not in by_fn)

print(f"OOB_CURSOR_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
