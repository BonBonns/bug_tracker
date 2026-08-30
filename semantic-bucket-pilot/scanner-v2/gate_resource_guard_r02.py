#!/usr/bin/env python3
"""RESOURCE-GUARD-R02 validation gate: 16 required synthetic controls (frozen real Joern
v4.0.608 output under study/resource_guard_r02/), all against the NEUTRAL-NAMED
SYNTHETIC_CONTRACTS entries (FactoryResource/Acquire/isInvalid, Factory/Make) --
deliberately decoupled from node-addon-api's real naming, so passing this gate demonstrates
the R02 ALGORITHM generalizes structurally, not that it was tuned to recognize the real
library. The real Napi::Buffer contract (resource_contracts_r02.py's REAL_CONTRACTS) is
used ONLY by the separate blind-test script against a real npm package -- see
RESOURCE_GUARD_R02.md's "Freeze, then blind test" section; this gate must be green BEFORE
that blind test is run, and this file is not touched again after that point (see the
recorded hash in RESOURCE_GUARD_R02.md).

Every fixture here is real Joern output from a real, minimal, single-TU c2cpg export -- no
synthetic JSON facts, no hand-built graphs. resource_guard_verdict_r02.py is exercised
exactly as it runs in production (RAW_DIR -> OUT.json), not via internal function calls.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "resource_guard_verdict_r02.py"
STUDY = HERE / "study" / "resource_guard_r02"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(rawdir, outname):
    outpath = HERE / (outname + ".json")
    subprocess.run([sys.executable, str(CAP), str(STUDY / rawdir), str(outpath)], check=True)
    return json.loads(outpath.read_text())


def verdicts(d):
    return sorted(f["verdict"] for f in d["findings"])


CONTROLS = [
    ("raw_r02c01_missing_guard", "factory result used without a guard",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c02_correct_guard", "correct isInvalid() failure guard (terminating)",
     ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
    ("raw_r02c03_inverted_predicate", "inverted predicate",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c04_check_after_use", "check after first use",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c05_check_different_object", "check on a different result object",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c06_called_twice_one_checked", "factory called twice, only one result checked",
     ["VALUE_ACQUISITION_GUARD_ESTABLISHED", "VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c07_result_aliased", "result copied to a one-hop reference alias",
     ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
    ("raw_r02c08_non_dominating_guard", "non-dominating guard",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c09_nonterminating_failure_branch", "failure branch that does not terminate",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c10_exceptions_enabled_try_catch",
     "exceptions-enabled configuration (real try/catch, invisible to exported CPG facts)",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c11_exceptions_disabled_loop_shaped",
     "exceptions-disabled configuration (the contract's own assumed config, loop-shaped)",
     ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
    ("raw_r02c12_unrelated_class", "unrelated uncontracted class with Acquire()/isInvalid()",
     ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c13_no_size_argument", "factory without the contract's curated size argument",
     ["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"]),
    ("raw_r02c15_unresolved_temporary_result", "unnamed/chained temporary result",
     ["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"]),
    ("raw_r02c16_instance_factory", "INSTANCE_FACTORY acquisition kind (bonus control)",
     ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
]
for rawdir, label, expected in CONTROLS:
    d = run(rawdir, f"out_{rawdir}")
    ck(f"control: {label} -> {expected}", verdicts(d) == sorted(expected))

# --- Two "no finding at all" / identity-specific checks ---
d14 = run("raw_r02c14_zero_length_valid", "out_r02c14")
ck("control: attacker-independent size (literal 0, a legitimately valid empty acquisition) "
   "-- ZERO findings, SIZE_ATTACKER_INDEPENDENT",
   d14["findings"] == [] and d14["classification"].get("SIZE_ATTACKER_INDEPENDENT") == 1)

d05 = run("raw_r02c05_check_different_object", "out_r02c05_check")
ck("control: check on a different object -- the finding names 'r' (the unguarded one), "
   "not 'g' (which has its own guard but is never used, so contributes no finding)",
   d05["findings"][0]["object"] == "r" and d05["classification"].get("RESOURCE_ACQUIRED_NO_USE") == 1)

d12 = run("raw_r02c12_unrelated_class", "out_r02c12_check")
ck("control: unrelated class -- OtherResource's own Acquire()/isInvalid() is rejected via "
   "ACQUISITION_SIGNATURE_UNRECOGNIZED (qualifier_type mismatch), not silently ignored",
   d12["classification"].get("ACQUISITION_SIGNATURE_UNRECOGNIZED") == 1)

# --- Property-classification discipline: NEVER a CWE-787/capacity claim anywhere ---
all_findings = []
for rawdir, _label, _exp in CONTROLS:
    d = json.loads((HERE / f"out_{rawdir}.json").read_text())
    all_findings.extend(d["findings"])
all_findings.extend(d14["findings"] + d05["findings"] + d12["findings"])
ck("no finding anywhere carries a cwe_hint/capacity claim -- IsEmpty()-shaped predicates "
   "prove handle validity, never destination capacity (see resource_guard_verdict_r02.py's "
   "module docstring)",
   all("cwe_hint" not in f for f in all_findings))
ck("every VALUE_ACQUISITION_GUARD_MISSING finding discloses its "
   "applicable_exception_configuration_assumed and evidence_note explicitly",
   all(("applicable_exception_configuration_assumed" in f and "evidence_note" in f)
       for f in all_findings if f["verdict"] == "VALUE_ACQUISITION_GUARD_MISSING"))

print(f"RESOURCE_GUARD_R02_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
