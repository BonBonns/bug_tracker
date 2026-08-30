#!/usr/bin/env python3
"""RESOURCE-GUARD-R02 blind-test reproduction: re-runs the FROZEN R02 pipeline (unmodified
since gate_resource_guard_r02.py's own 20/20 freeze -- see RESOURCE_GUARD_R02.md's "Freeze"
section for the recorded md5s, re-checked below) against the real, un-curated npm package
site selected for the blind test (Automattic/node-canvas, src/Canvas.cc, streamPDF), and
asserts the output matches the result RECORDED in RESOURCE_GUARD_R02.md's "Blind test"
section, unmodified after the fact.

This is a SEPARATE script from gate_resource_guard_r02.py on purpose: that gate's whole
point is "20/20 on neutral synthetic controls, verified BEFORE any real npm package is
inspected" -- it must stay a pre-blind-test artifact, never touched again. This script
verifies the post-blind-test artifact instead: that the frozen algorithm, run against real
node-canvas facts, reproduces exactly the recorded (honest-abstention) result, not a
different one -- i.e. that the recorded result in the .md file is not stale relative to the
committed code and fixture facts.
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

ck("blind-test run against real node-canvas streamPDF facts reproduces the recorded "
   "RESOURCE_GUARD_R02.md result exactly (honest abstention -- ACQUISITION_NAME_MATCH_"
   "CANDIDATE=1, ACQUISITION_SIGNATURE_UNRECOGNIZED=1, zero findings; NOT a detection)",
   actual == expected)
ck("the recorded result contains zero findings (R02 abstained rather than guessing on a "
   "real site outside its curated contract's exact scope -- see RESOURCE_GUARD_R02.md's "
   "'Blind test' section for the three independently-confirmed reasons)",
   actual["findings"] == [])

print(f"RESOURCE_GUARD_R02_BLINDTEST_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
