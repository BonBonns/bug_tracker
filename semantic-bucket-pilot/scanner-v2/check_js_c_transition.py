#!/usr/bin/env python3
"""Measures the destination-capacity-write scanner (oob_runtime_capacity_v2.py /
analyze_operations_v2) against a real fixture from the js_c_transition corpus
(study/js_c_transition/README.md). Frozen real Joern v4.0.608 output under
study/js_c_transition/raw_case_hermes_apply/, same convention as lockcap.

This is a MEASUREMENT, not a pass/fail suite over "expected correct" behavior -- the one
assertion below pins a CONFIRMED, EXPLAINED COVERAGE GAP (the scanner produces zero
findings for a real CWE-787 bug) as an honest regression baseline. Read the comment before
treating "PASS" as "the scanner caught the bug" -- it did not, and this file says why.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import oob_runtime_capacity_v2 as v2

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- case_hermes_apply: real Facebook Hermes hermesBuiltinApply, vulnerable revision
# 82f0f971 (CVE-2020-1896, CWE-787). The bug: ScopedNativeCallFrame's constructor sizes
# and allocates `len` (attacker-controlled, from a JS array's .length) register slots on
# Hermes's bounded runtime register stack; if that allocation would overflow the stack, it
# sets overflowed_ and returns WITHOUT a valid frame -- the caller must check overflowed()
# before touching the frame. hermesBuiltinApply doesn't: it writes `len` HermesValues into
# newFrame->getArgRef(i) unconditionally in a loop, so on overflow it writes through an
# invalid/never-allocated frame. This is a genuine, real, in-the-wild destination-capacity
# write bug -- but NOT the representation shape any of the 4 capabilities model (fixed
# stack array w/ direct index, memcpy-family wrapper, pointer-walk *p++=, external decoder
# contract). The write is an assignment to the return value of a C++ operator-> + method
# call (newFrame->getArgRef(i) = ...), and the "capacity" is a manipulated RAII object's
# constructor-time allocation, not a declared array or a call this scanner's
# CALLEE_CONTRACTS dict (memcpy/memmove/memset/wmemcpy/PORT_Memcpy/PORT_Memmove/
# HMAC_Finish -- 7 names total) recognizes at all.
r = v2.analyze_operations_v2(str(HERE / "study" / "js_c_transition" / "raw_case_hermes_apply" / "program.json"))
recs, _trans = r
ck("case_hermes_apply: CONFIRMED COVERAGE GAP -- the scanner finds ZERO write operations "
   "in this real CWE-787 function, not because it correctly judged the write safe, but "
   "because newFrame->getArgRef(i)=... is never candidate-recognized in the first place: "
   "it's a write through a C++ operator overload's return value, not a call to any of the "
   "7 CALLEE_CONTRACTS-listed memcpy-family functions and not an indexed access to a "
   "declared fixed array. Zero recs means zero operations were even considered, not zero "
   "unsafe verdicts among considered ones -- confirmed by Joern's own reaching-def log "
   "showing hermesBuiltinApply was fully parsed and analyzed (131 reaching-def facts).",
   recs == [])

print(f"JS_C_TRANSITION_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
