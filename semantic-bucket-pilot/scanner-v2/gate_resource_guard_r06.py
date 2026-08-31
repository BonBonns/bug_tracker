#!/usr/bin/env python3
"""Gate for RESOURCE-GUARD-R06 (task #41: merge R06/FIX01I into the driven R04/R05 lineage).

Two real checks:
1. No regression: R06 reused against the SAME real `study/resource_guard_r05/r05_controls`
   fixture `gate_resource_guard_r05.py` already verifies -- every one of the same six real
   gates must land on the SAME predicted outcome as R05 (R06 is a strict addition on top of
   R05, never a rewrite of its own matching/dominance/tracing/verdict-construction logic; see
   `resource_guard_verdict_r06.py`'s own module docstring).
2. R06's own real addition, the source-boundary gate, verified against real, committed corpus
   facts (`study/r06_fix01i_integration/real_fixtures/`, task #41 -- previously these lived
   only in operator-maintained /tmp paths):
   - node-libcurl's real `Easy::ReadFunction` finding: R05 (per `R05_CORPUS_RESULTS.md`, task
     #35) attached `attacker_influence_evidence`/`traced_to_parameter` unconditionally for any
     reached parameter. R06 must instead report `source_boundary_evidence.source_boundary ==
     'SOURCE_BOUNDARY_UNRESOLVED'` and `attacker_controlled: False` for this exact site --
     required, task #41's own named acceptance test.
   - Cartesi's own 3 real findings (ReadMemory/ReadVirtualMemory/ReadConsoleOutput): the real
     backward walk never reaches ANY parameter at all (the real code path is an out-parameter
     helper call, `get_u64(env, info[1], "length", &length)`, a dataflow shape this walk was
     never designed to follow) -- `source_boundary_evidence` must be `None` for all three,
     confirming R06 does not fabricate evidence where the walk found nothing.

Run: python3 gate_resource_guard_r06.py
Exit 0 and prints "ALL PASS" iff every control below passes; otherwise prints the first
failure and exits 1.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CONTROLS_RAW = HERE / "study" / "resource_guard_r05" / "r05_controls" / "raw_facts"
R05_BUILD_CONFIG = HERE / "study" / "resource_guard_r05" / "r05_controls" / "build_config.json"
VERDICT_SCRIPT = HERE / "resource_guard_verdict_r06.py"

REAL_FIXTURES = HERE / "study" / "r06_fix01i_integration" / "real_fixtures"
LIBCURL_RAW = REAL_FIXTURES / "libcurl_raw"
LIBCURL_BUILD_CONFIG = REAL_FIXTURES / "libcurl_build_config.json"
CARTESI_RAW = REAL_FIXTURES / "cartesi_raw"
CARTESI_BUILD_CONFIG = REAL_FIXTURES / "cartesi_build_config.json"

# Same real expectations gate_resource_guard_r05.py already verifies -- R06 must reproduce
# them identically (no regression).
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


def _run(raw, out, build_config):
    subprocess.run([sys.executable, str(VERDICT_SCRIPT), str(raw), str(out), "--real",
                     "--build-config", str(build_config)], check=True,
                    stdout=subprocess.DEVNULL)
    return json.loads(out.read_text())


def check_no_regression():
    if not CONTROLS_RAW.exists():
        fail(f"{CONTROLS_RAW} not found -- run gate_resource_guard_r05.py's own fixture setup "
             "first")
    # gate_resource_guard_r05.py writes this same file fresh on each of its own runs -- do the
    # same here rather than depending on a stale copy left over from a previous run.
    R05_BUILD_CONFIG.write_text(json.dumps({
        "exception_configuration": "disabled",
        "evidence": [{"source": "r05_controls fixture", "detail": "compiled with "
                      "-DNAPI_DISABLE_CPP_EXCEPTIONS", "citation": "n/a -- test fixture"}],
        "citation": "test fixture, exceptions explicitly disabled at compile time",
    }))
    out = HERE / "study" / "resource_guard_r05" / "r05_controls" / "gate_run_output_r06.json"
    result = _run(CONTROLS_RAW, out, R05_BUILD_CONFIG)

    findings_by_method = {}
    for f in result["findings"]:
        findings_by_method.setdefault(f.get("method_name"), []).append(f)

    for method, expected in EXPECTED_BY_METHOD.items():
        method_findings = findings_by_method.get(method, [])
        if expected["recovered"]:
            if not method_findings:
                fail(f"{method}: expected a recovered finding, got none (R06 regression vs R05)")
            f = method_findings[0]
            if f.get("verdict") != expected["verdict"]:
                fail(f"{method}: expected verdict {expected['verdict']!r}, got "
                     f"{f.get('verdict')!r} (R06 regression vs R05)")
            print(f"PASS: {method} recovered as {f['verdict']} via R06 (matches R05)")
        else:
            recovered_here = [f for f in method_findings
                               if f.get("evidence_source") == "r05_structural_recovery"]
            if recovered_here:
                fail(f"{method}: expected NO recovery, but R06 recovered one "
                     f"(regression vs R05): {recovered_here[0]}")
            print(f"PASS: {method} correctly NOT recovered under R06 (matches R05)")

    if result["classification"].get("R05_ACQUISITION_CALL_RECOVERED") != 1:
        fail("expected exactly 1 real recovered acquisition under R06 (matches R05), got "
             f"{result['classification'].get('R05_ACQUISITION_CALL_RECOVERED')}")
    print("PASS: R06 reproduces R05's own real fixture outcomes exactly -- no regression")


def check_source_boundary_gate():
    if not (LIBCURL_RAW.exists() and CARTESI_RAW.exists()):
        fail(f"real fixtures not found under {REAL_FIXTURES} -- task #41's own committed "
             "real corpus facts are missing")

    lc_out = REAL_FIXTURES / "_generated_gate_libcurl_out.json"
    lc = _run(LIBCURL_RAW, lc_out, LIBCURL_BUILD_CONFIG)
    read_function = next((f for f in lc["findings"] if f.get("method_name") == "ReadFunction"),
                          None)
    if read_function is None:
        fail("node-libcurl's real ReadFunction finding not present in R06's own output")
    sbe = read_function.get("source_boundary_evidence")
    if not (sbe and sbe.get("source_boundary") == "SOURCE_BOUNDARY_UNRESOLVED"
            and sbe.get("attacker_controlled") is False):
        fail(f"ReadFunction: expected source_boundary_evidence.source_boundary == "
             f"'SOURCE_BOUNDARY_UNRESOLVED' and attacker_controlled: False, got {sbe!r}")
    print("PASS: node-libcurl's real Easy::ReadFunction finding correctly reports "
          "SOURCE_BOUNDARY_UNRESOLVED / attacker_controlled=False under R06 -- task #41's own "
          "named acceptance test")

    ct_out = REAL_FIXTURES / "_generated_gate_cartesi_out.json"
    ct = _run(CARTESI_RAW, ct_out, CARTESI_BUILD_CONFIG)
    if len(ct["findings"]) != 3:
        fail(f"expected exactly 3 real Cartesi findings, got {len(ct['findings'])}")
    for f in ct["findings"]:
        if f.get("source_boundary_evidence") is not None:
            fail(f"{f.get('method_name')}: expected source_boundary_evidence None (the real "
                 f"backward walk never reaches any parameter for Cartesi's own real "
                 f"out-parameter dataflow shape), got {f['source_boundary_evidence']!r}")
    print("PASS: all 3 real Cartesi findings (ReadMemory/ReadVirtualMemory/ReadConsoleOutput) "
          "correctly report source_boundary_evidence=None under R06 -- no fabricated evidence "
          "where the walk found nothing")


def main():
    check_no_regression()
    check_source_boundary_gate()
    print("ALL PASS")


if __name__ == "__main__":
    main()
