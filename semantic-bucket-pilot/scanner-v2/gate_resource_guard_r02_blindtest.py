#!/usr/bin/env python3
"""RESOURCE-GUARD-R02 blind-test reproduction: re-runs the FROZEN R02 pipeline (unmodified
since gate_resource_guard_r02.py's own 20/20 freeze -- see RESOURCE_GUARD_R02.md's "Freeze"
section for the recorded md5s, re-checked below) against each real npm-package site recorded
in RESOURCE_GUARD_R02.md's "Blind test" sections, and asserts each output matches its
recorded result, unmodified after the fact.

Neither recorded case is a detection of a real vulnerability -- both are correct,
out-of-contract ABSTENTIONS, for two DIFFERENT, independently-diagnosed reasons (see
RESOURCE_GUARD_R02.md for the full write-up of each):

- node-canvas (`raw_case_node_canvas_streampdf`): uses Buffer<T>::New(env, data, len), the
  3-argument EXTERNAL-DATA overload, not the 2-argument ALLOCATING overload
  (Buffer<T>::New(env, len)) REAL_CONTRACTS["Napi::Buffer"] curates -- genuinely
  out-of-contract by overload arity, compounded by an unresolved methodFullName at the
  c2cpg frontend level and a base-class-typed (Napi::Value, not Buffer) result variable.
- cartesi/rollups-ts's @cartesi/machine (`raw_case_cartesi_readmemory`): uses the CORRECT
  2-argument allocating overload, with an attacker-influenced length, a plausible
  exceptions-disabled build (NAPI_DISABLE_CPP_EXCEPTIONS in binding.gyp, no try/catch), a
  genuine downstream use, and no guard at all -- i.e. it satisfies every property this
  contract cares about, and STILL was not detected, because the curated `qualifier_type`
  ("Buffer") lacks the `Napi::` namespace prefix that c2cpg's real methodFullName carries
  ("Napi.Buffer.New:..."), a narrow, precisely-isolated contract-curation gap.

Neither missing check is evidence of CWE-787 or any other memory-corruption defect by itself
-- IsEmpty() proves handle validity under an applicable exception configuration, never buffer
capacity -- and this script makes no vulnerability claim about either real site. It exists
only to catch REGRESSION -- a recorded result silently going stale relative to the committed
code/facts -- not to claim either site was meaningfully scanned for a real defect.

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
STUDY = HERE / "study" / "resource_guard_r02"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# The freeze hashes recorded in RESOURCE_GUARD_R02.md -- if either file has changed since
# the blind tests were recorded, that's real news, and this check should fail loudly rather
# than silently re-validate a since-modified algorithm against old recorded results.
ck("resource_guard_verdict_r02.py unchanged since the recorded blind tests "
   "(md5 016b1b327d22418b326b3b1a3fafd91d)",
   hashlib.md5(CAP.read_bytes()).hexdigest() == "016b1b327d22418b326b3b1a3fafd91d")
ck("resource_contracts_r02.py unchanged since the recorded blind tests "
   "(md5 91df28ae16f36bfa1656bfb6529a1eb5)",
   hashlib.md5(CONTRACTS.read_bytes()).hexdigest() == "91df28ae16f36bfa1656bfb6529a1eb5")

CASES = [
    ("raw_case_node_canvas_streampdf",
     "node-canvas streamPDF (out-of-contract: 3-arg external-data overload, not the "
     "curated 2-arg allocating overload)"),
    ("raw_case_cartesi_readmemory",
     "cartesi @cartesi/machine Machine::ReadMemory (satisfies every required real-site "
     "property, still abstains: qualifier_type lacks the real Napi:: namespace prefix)"),
]
for case_dir, label in CASES:
    case_path = STUDY / case_dir
    outpath = HERE / f"out_r02_blindtest_{case_dir}.json"
    subprocess.run(
        [sys.executable, str(CAP), str(case_path), str(outpath), "--real"], check=True
    )
    actual = json.loads(outpath.read_text())
    expected = json.loads((case_path / "expected_output.json").read_text())

    ck(f"{label}: run reproduces the recorded RESOURCE_GUARD_R02.md result exactly",
       actual == expected)
    ck(f"{label}: recorded result contains zero findings (an out-of-contract abstention, "
       "not a detection or a vulnerability claim about the real site)",
       actual["findings"] == [])

print(f"RESOURCE_GUARD_R02_BLINDTEST_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
