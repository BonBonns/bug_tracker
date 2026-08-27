#!/usr/bin/env python3
"""OOB-CALLSINK-R01 gate. Validates oob_call_sink_verdict.py -- the contract-driven
generalization of COPY_LENGTH's memcpy-family-only allowlist to any callee with a
verified entry in callee_contracts.py, via the BufferOperationFact intermediate
representation. The key property under test is NOT just "does it flag the right
things" but "does it stay silent on an unknown callee" -- i.e. that unresolved
contracts really do remain unresolved, structurally, not just by convention."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
TOOLS = H.parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("ocs", TOOLS / "oob_call_sink_verdict.py")
ocs = importlib.util.module_from_spec(spec); spec.loader.exec_module(ocs)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

c = ocs.emit_candidates(str(H / "fixtures" / "controls.program.json"))
by_fn = {x['function_id']: x for x in c}

ck("exactly 3 candidates (memcpy, HMAC_Finish, PORT_Memset -- unknown callee excluded)",
   len(c) == 3)

ck("vuln_memcpy_unbounded FLAGGED via the memcpy contract",
   940000000001 in by_fn and by_fn[940000000001]['callee'] == 'memcpy'
   and by_fn[940000000001]['dest'] == 'buf' and by_fn[940000000001]['elem_count'] == 16)

ck("vuln_hmacfinish_unbounded FLAGGED via the HMAC_Finish contract (dest_arg=1, width_arg=3, offset shape)",
   940000000002 in by_fn and by_fn[940000000002]['callee'] == 'HMAC_Finish'
   and by_fn[940000000002]['dest'] == 'buf + off' and by_fn[940000000002]['array_base'] == 'buf'
   and by_fn[940000000002]['offset_shape'] is True and by_fn[940000000002]['width_expr'] == 'hashLen'
   and by_fn[940000000002]['elem_count'] == 24)

ck("guarded_sizeof suppressed (len > sizeof(buf) credited)", 940000000003 not in by_fn)

ck("unknown_callee_abstain: NO candidate (some_random_write_fn has no contract entry -- "
   "unresolved contracts stay unresolved, not guessed at)",
   940000000004 not in by_fn)

ck("offset_literal_safe suppressed (16+8==24, pure arithmetic, no guess)",
   940000000005 not in by_fn)

ck("portmemset_unbounded FLAGGED via the PORT_Memset contract (a THIRD distinct callee, "
   "proving this producer generalizes rather than special-casing memcpy/HMAC_Finish)",
   940000000006 in by_fn and by_fn[940000000006]['callee'] == 'PORT_Memset')

print(f"OOB_CALLSINK_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
