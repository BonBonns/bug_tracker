#!/usr/bin/env python3
"""Gate for RESOURCE-GUARD-R05. Exercises `study/resource_guard_r05/r05_controls`'s real,
Joern-verified facts (six functions in one real file, real #include <napi.h>, real c2cpg
--include/--define -- see the fixture's own module comment and R05_DESIGN.md) through
`resource_guard_verdict_r05.py --real`, and checks every one of the six real gates lands on
its predicted outcome. Also checks R01-R04 remain byte-identical to their
`npm_corpus/ANALYZER_FREEZE.md`-recorded hashes -- this file adding R05 must never silently
modify any of them.

Run: python3 gate_resource_guard_r05.py
Exit 0 and prints "ALL PASS" iff every control below passes; otherwise prints the first
failure and exits 1.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CONTROLS_RAW = HERE / "study" / "resource_guard_r05" / "r05_controls" / "raw_facts"
VERDICT_SCRIPT = HERE / "resource_guard_verdict_r05.py"

FROZEN_HASHES = {
    "resource_guard_verdict.py": "ce641e1acf05ac90af9ea942c934f62e",
    "resource_guard_verdict_r02.py": "016b1b327d22418b326b3b1a3fafd91d",
    "resource_contracts_r02.py": "91df28ae16f36bfa1656bfb6529a1eb5",
    "resource_guard_verdict_r03.py": "81ce5856f142d77f9da33472faafc65a",
    "resource_contracts_r03.py": "7a73af8853c28ec3edba4fd078d67305",
    "resource_guard_verdict_r04.py": "b8c0e058b832b428d739b048d0f34c83",
    "resource_contracts_r04.py": "68d2448e36556c4442bc10065b504ed3",
}

EXPECTED_BY_METHOD = {
    "PositiveBufferNew": {"recovered": True, "verdict": "VALUE_ACQUISITION_GUARD_MISSING"},
    "WrongResultTypeTypeError": {"recovered": False, "reason": "R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED"},
    "LookalikeOtherBuffer": {"recovered": False, "reason": "R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED"},
    "UnrelatedWidgetNew": {"recovered": False, "reason": "R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED"},
    "ExternalDataOverload": {"recovered": False, "reason": "R05_RECOVERY_ARITY_UNRECOGNIZED"},
    "AutoDeducedLocal": {"recovered": False, "reason": "R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED"},
}


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check_frozen_hashes():
    for fname, expected in FROZEN_HASHES.items():
        path = HERE / fname
        actual = hashlib.md5(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{fname} hash mismatch -- expected {expected}, got {actual} "
                 f"(R01-R04 must stay byte-identical; R05 must never modify them)")
    print(f"PASS: all {len(FROZEN_HASHES)} R01-R04 files byte-identical to their frozen hashes")


def check_controls():
    if not CONTROLS_RAW.exists():
        fail(f"{CONTROLS_RAW} not found -- run the fixture's own c2cpg/export pass first "
             "(see r05_controls/fixture_source.cpp's own header comment)")
    out = HERE / "study" / "resource_guard_r05" / "r05_controls" / "gate_run_output.json"
    build_config = HERE / "study" / "resource_guard_r05" / "r05_controls" / "build_config.json"
    build_config.write_text(json.dumps({
        "exception_configuration": "disabled",
        "evidence": [{"source": "r05_controls fixture", "detail": "compiled with "
                      "-DNAPI_DISABLE_CPP_EXCEPTIONS", "citation": "n/a -- test fixture"}],
        "citation": "test fixture, exceptions explicitly disabled at compile time",
    }))
    subprocess.run([sys.executable, str(VERDICT_SCRIPT), str(CONTROLS_RAW), str(out),
                     "--real", "--build-config", str(build_config)], check=True,
                    stdout=subprocess.DEVNULL)
    result = json.loads(out.read_text())

    findings_by_method = {}
    for f in result["findings"]:
        findings_by_method.setdefault(f.get("method_name"), []).append(f)

    classification = result["classification"]

    for method, expected in EXPECTED_BY_METHOD.items():
        method_findings = findings_by_method.get(method, [])
        if expected["recovered"]:
            if not method_findings:
                fail(f"{method}: expected a recovered finding, got none")
            f = method_findings[0]
            if f.get("evidence_source") != "r05_structural_recovery":
                fail(f"{method}: finding present but evidence_source is "
                     f"{f.get('evidence_source')!r}, not 'r05_structural_recovery'")
            if f.get("verdict") != expected["verdict"]:
                fail(f"{method}: expected verdict {expected['verdict']!r}, got "
                     f"{f.get('verdict')!r}")
            print(f"PASS: {method} recovered as {f['verdict']} via r05_structural_recovery")
        else:
            recovered_here = [f for f in method_findings
                               if f.get("evidence_source") == "r05_structural_recovery"]
            if recovered_here:
                fail(f"{method}: expected NO recovery (negative control), but got a "
                     f"recovered finding: {recovered_here[0]}")
            print(f"PASS: {method} correctly NOT recovered "
                  f"(expected rejection: {expected['reason']})")

    if classification.get("R05_ACQUISITION_CALL_RECOVERED") != 1:
        fail("expected exactly 1 R05_ACQUISITION_CALL_RECOVERED across the whole fixture, "
             f"got {classification.get('R05_ACQUISITION_CALL_RECOVERED')}")
    print("PASS: exactly 1 real recovered acquisition across the fixture "
          "(the other 5 are real, distinct negative controls)")


def main():
    check_frozen_hashes()
    check_controls()
    print("ALL PASS")


if __name__ == "__main__":
    main()
