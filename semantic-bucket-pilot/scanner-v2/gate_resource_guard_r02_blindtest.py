#!/usr/bin/env python3
"""RESOURCE-GUARD-R02 blind-test reproduction: re-runs the FROZEN R02 pipeline (unmodified
since gate_resource_guard_r02.py's own 20/20 freeze -- see RESOURCE_GUARD_R02.md's "Freeze"
section for the recorded md5s, re-checked below) against Automattic/node-canvas's
src/Canvas.cc, streamPDF, and asserts the output matches the result RECORDED in
RESOURCE_GUARD_R02.md's "Blind test" section, unmodified after the fact.

IMPORTANT -- this site is NOT an applicable test of the curated contract (see
RESOURCE_GUARD_R02.md's "Correction" paragraph): it uses Buffer<T>::New(env, data, len), the
3-argument EXTERNAL-DATA overload, not the 2-argument ALLOCATING overload
(Buffer<T>::New(env, len)) that REAL_CONTRACTS["Napi::Buffer"] curates. The recorded
ACQUISITION_SIGNATURE_UNRECOGNIZED / zero-findings result is therefore an OUT-OF-CONTRACT
ABSTENTION, not a failed detection -- there is no vulnerability claim to make or fail to make
about streamPDF here, and a missing IsEmpty() at this site is not itself evidence of CWE-787
or any other memory-corruption defect (IsEmpty() proves handle validity under an applicable
exception configuration, never buffer capacity). This script exists only to catch
REGRESSION -- the recorded result silently going stale relative to the committed code/facts
-- not to claim the site was meaningfully scanned. A real cross-contract-portability blind
test still requires a site matching the 2-argument allocating overload, attacker-influenced
length, an applicable exceptions-disabled configuration, and a genuine downstream use -- see
RESOURCE_GUARD_R02.md's "Next blind target" section.

This is a SEPARATE script from gate_resource_guard_r02.py on purpose: that gate's whole
point is "20/20 on neutral synthetic controls, verified BEFORE any real npm package is
inspected" -- it must stay a pre-blind-test artifact, never touched again.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "resource_guard_verdict_r02.py"
CONTRACTS = HERE / "resource_contracts_r02.py"
CASE_DIR = HERE / "study" / "resource_guard_r02" / "raw_case_node_canvas_streampdf"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# The freeze hashes recorded in RESOURCE_GUARD_R02.md -- if either file has changed since
# the blind test was recorded, that's real news, and this check should fail loudly rather
# than silently re-validate a since-modified algorithm against an old recorded result.
ck("resource_guard_verdict_r02.py unchanged since the recorded blind test "
   "(md5 016b1b327d22418b326b3b1a3fafd91d)",
   hashlib.md5(CAP.read_bytes()).hexdigest() == "016b1b327d22418b326b3b1a3fafd91d")
ck("resource_contracts_r02.py unchanged since the recorded blind test "
   "(md5 91df28ae16f36bfa1656bfb6529a1eb5)",
   hashlib.md5(CONTRACTS.read_bytes()).hexdigest() == "91df28ae16f36bfa1656bfb6529a1eb5")

outpath = HERE / "out_r02_blindtest_node_canvas.json"
subprocess.run(
    [sys.executable, str(CAP), str(CASE_DIR), str(outpath), "--real"], check=True
)
actual = json.loads(outpath.read_text())
expected = json.loads((CASE_DIR / "expected_output.json").read_text())

ck("run against real node-canvas streamPDF facts reproduces the recorded "
   "RESOURCE_GUARD_R02.md result exactly (out-of-contract abstention -- "
   "ACQUISITION_NAME_MATCH_CANDIDATE=1, ACQUISITION_SIGNATURE_UNRECOGNIZED=1, zero "
   "findings; this call uses the 3-arg external-data overload, not the 2-arg allocating "
   "overload this contract curates, so this is not a failed detection)",
   actual == expected)
ck("the recorded result contains zero findings (correct behavior for a call outside this "
   "contract's curated overload -- see RESOURCE_GUARD_R02.md's 'Correction' paragraph; "
   "this is not evidence about whether streamPDF is or isn't vulnerable)",
   actual["findings"] == [])

print(f"RESOURCE_GUARD_R02_BLINDTEST_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
