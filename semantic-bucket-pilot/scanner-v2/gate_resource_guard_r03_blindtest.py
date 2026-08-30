#!/usr/bin/env python3
"""RESOURCE-GUARD-R03 blind-test reproduction: re-runs the FROZEN R03 pipeline (unmodified
since gate_resource_guard_r03.py's own 33/33 freeze -- see RESOURCE_GUARD_R03.md's "Freeze"
section for the recorded md5s, re-checked below) against `@julusian/jpeg-turbo`'s
`src/decompress.cc`, `DecompressInner`, and asserts the output matches the result RECORDED in
RESOURCE_GUARD_R03.md's "R03 blind test" section, unmodified after the fact.

This is R03's actual blind test, per the evaluation boundary RESOURCE_GUARD_R03.md states:
R02 remains the frozen blind-test miss (unrewritten); Cartesi is R03's development/recovery
case (it motivated the correction, so it cannot also be R03's blind holdout); this jpeg-turbo
site is genuinely untouched -- independently verified as published on the npm registry, its
real source read directly, and the frozen R03 pipeline run against it with no modification to
resource_guard_verdict_r03.py or resource_contracts_r03.py made in response.

The recorded VALUE_ACQUISITION_GUARD_MISSING finding is real evidence of cross-contract
structural portability on APPLICABLE real code (correct overload, correct namespace,
attacker-influenced size, downstream use, no dominating guard) -- it is NOT a confirmed
vulnerability claim, NOT automatically CWE-787, and NOT proof of exploitable memory
corruption. It additionally carries one disclosed, material caveat this script's own
assertions preserve rather than smooth over: this project's real build configuration most
likely enables C++ exceptions (no NAPI_DISABLE_CPP_EXCEPTIONS anywhere, and node-addon-api's
own default-resolution logic enables exceptions absent an explicit compiler-level opt-out) --
the OPPOSITE of this contract's own disclosed "exceptions_disabled" assumption -- so this
finding's practical applicability is less certain than Cartesi's own recovery finding, where
that assumption was independently corroborated by an explicit build-config macro.

This is a SEPARATE script from gate_resource_guard_r03.py on purpose: that gate's whole point
is "controls + Cartesi recovery pass BEFORE any third real npm package is inspected" -- it
must stay a pre-blind-test artifact, never touched again.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "resource_guard_verdict_r03.py"
CONTRACTS = HERE / "resource_contracts_r03.py"
CASE_DIR = HERE / "study" / "resource_guard_r03" / "raw_case_jpegturbo_decompress"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


ck("resource_guard_verdict_r03.py unchanged since the recorded blind test "
   "(md5 81ce5856f142d77f9da33472faafc65a)",
   hashlib.md5(CAP.read_bytes()).hexdigest() == "81ce5856f142d77f9da33472faafc65a")
ck("resource_contracts_r03.py unchanged since the recorded blind test "
   "(md5 7a73af8853c28ec3edba4fd078d67305)",
   hashlib.md5(CONTRACTS.read_bytes()).hexdigest() == "7a73af8853c28ec3edba4fd078d67305")

outpath = HERE / "out_r03_blindtest_jpegturbo.json"
subprocess.run(
    [sys.executable, str(CAP), str(CASE_DIR), str(outpath), "--real"], check=True
)
actual = json.loads(outpath.read_text())
expected = json.loads((CASE_DIR / "expected_output.json").read_text())

ck("run against real jpeg-turbo DecompressInner facts reproduces the recorded "
   "RESOURCE_GUARD_R03.md result exactly", actual == expected)
ck("the recorded result is VALUE_ACQUISITION_GUARD_MISSING on a genuinely untouched, "
   "npm-registry-published real site -- structural portability evidence, NOT a vulnerability "
   "claim, NOT automatically CWE-787, NOT proof of exploitable memory corruption",
   [f["verdict"] for f in actual["findings"]] == ["VALUE_ACQUISITION_GUARD_MISSING"])
ck("the finding's own evidence_note still explicitly disclaims a vulnerability/CWE-787/"
   "exploit claim",
   all("not a vulnerability claim" in f.get("evidence_note", "")
       and "CWE-787" in f.get("evidence_note", "")
       for f in actual["findings"]))
ck("attacker_influence_evidence is (still, honestly) absent from this finding -- the real "
   "out-parameter data-flow pattern (tjDecompressHeader(..., &props.resWidth, "
   "&props.resHeight)) is not one backward_attacker_trace (unmodified) follows, the same "
   "disclosed limitation as Cartesi's own recovery finding",
   all("attacker_influence_evidence" not in f for f in actual["findings"]))

print(f"RESOURCE_GUARD_R03_BLINDTEST_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
