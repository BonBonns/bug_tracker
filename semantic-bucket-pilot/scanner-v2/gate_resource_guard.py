#!/usr/bin/env python3
"""RESOURCE-GUARD-R01 validation gate: the 12 required synthetic controls (frozen real
Joern v4.0.608 output under study/resource_guard/, same convention as lockcap) PLUS the
real CVE-2020-1896 differential (vulnerable revision 82f0f971 vs. its own fix commit
86543ac4, Facebook Hermes hermesBuiltinApply -- study/js_c_transition/raw_case_hermes_apply
and study/resource_guard/raw_case_hermes_apply_patched).

Every fixture here is real Joern output from a real, minimal, single-TU c2cpg export --
no synthetic JSON facts, no hand-built graphs. resource_guard_verdict.py is exercised
exactly as it runs in production (RAW_DIR -> OUT.json), not via internal function calls.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "resource_guard_verdict.py"
STUDY = HERE / "study"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(rawdir_relative, outname):
    outpath = HERE / (outname + ".json")
    subprocess.run([sys.executable, str(CAP), str(STUDY / rawdir_relative), str(outpath)], check=True)
    return json.loads(outpath.read_text())


def verdict(d):
    return d["findings"][0]["verdict"] if d["findings"] else "NONE"


# --- The real CVE-2020-1896 differential (the whole point of this capability) ---
r_vuln = run("js_c_transition/raw_case_hermes_apply", "out_rg_vuln")
ck("real vulnerable Hermes revision (82f0f971): RESOURCE_GUARD_MISSING",
   verdict(r_vuln) == "RESOURCE_GUARD_MISSING")
ck("real vulnerable Hermes revision: unguarded write connected "
   "(downstream_write_evidence established, cwe_hint attached)",
   r_vuln["findings"][0].get("downstream_write_evidence") == "direct_assignment_through_resource"
   and "cwe_hint" in r_vuln["findings"][0])
ck("real vulnerable Hermes revision: the real attacker-influence chain is traced "
   "(len <- getLength(*argArray) <- argArray <- dyncastArg<JSArray>(1) <- args, a real "
   "parameter of hermesBuiltinApply) -- not just 'non-literal', the actual trace",
   r_vuln["findings"][0].get("attacker_influence_evidence", {}).get("traced_to_parameter") == "args")

r_patched = run("resource_guard/raw_case_hermes_apply_patched", "out_rg_patched")
ck("real PATCHED Hermes revision (86543ac4, the actual fix commit): "
   "RESOURCE_GUARD_ESTABLISHED", verdict(r_patched) == "RESOURCE_GUARD_ESTABLISHED")

# --- The 12 required synthetic controls (all real Joern facts, all in resource_guard/) ---
CONTROLS = [
    ("raw_c01_missing_check", "missing check", "RESOURCE_GUARD_MISSING"),
    ("raw_c02_correct_check", "correct dominating failure check", "RESOURCE_GUARD_ESTABLISHED"),
    ("raw_c03_inverted_check", "inverted check", "RESOURCE_GUARD_MISSING"),
    ("raw_c04_check_after_use", "check after first use", "RESOURCE_GUARD_MISSING"),
    ("raw_c05_check_different_object", "check on a different object", "RESOURCE_GUARD_MISSING"),
    ("raw_c06_non_dominating_branch", "non-dominating branch check", "RESOURCE_GUARD_MISSING"),
    ("raw_c07_alias_use", "alias of the same resource", "RESOURCE_GUARD_ESTABLISHED"),
    ("raw_c08_unrelated_overflowed", "unrelated overflowed() method (uncontracted class)",
     "RESOURCE_GUARD_MISSING"),
    ("raw_c10_unresolved_ctor", "unresolved constructor semantics", "RESOURCE_SEMANTICS_UNRESOLVED"),
    ("raw_c12_nonterminating_failure_branch", "failure branch that does not terminate",
     "RESOURCE_GUARD_MISSING"),
]
for rawdir, label, expected in CONTROLS:
    d = run(f"resource_guard/{rawdir}", f"out_rg_{rawdir}")
    ck(f"control: {label} -> {expected}", verdict(d) == expected)

# --- c05: confirm the finding is for the RIGHT object (f, guarded object is g) ---
d05 = run("resource_guard/raw_c05_check_different_object", "out_rg_c05_check")
ck("control: check on a different object -- the finding names 'f' (the unguarded one), "
   "not 'g' (which has its own guard but is never used, so contributes no finding)",
   d05["findings"][0]["object"] == "f" and d05["classification"].get("RESOURCE_ACQUIRED_NO_USE") == 1)

# --- Two "no finding at all" negative controls ---
d09 = run("resource_guard/raw_c09_infallible_raii", "out_rg_c09")
ck("control: infallible RAII object (uncontracted class, cannot fail) -- ZERO findings, "
   "not even RESOURCE_SEMANTICS_UNRESOLVED (never even considered a candidate)",
   d09["findings"] == [] and d09["classification"] == {})

d11 = run("resource_guard/raw_c11_attacker_independent_size", "out_rg_c11")
ck("control: attacker-independent size (a literal constant) -- ZERO findings even though "
   "the check is ALSO missing here (element 1 of FALLIBLE_BOUNDED_RESOURCE fails outright)",
   d11["findings"] == [] and d11["classification"].get("SIZE_ATTACKER_INDEPENDENT") == 1)

# --- Generalization check: OTHER real, independently-written ScopedNativeCallFrame call
# sites in the SAME Hermes revision (82f0f971), never tuned against, never CVE-2020-1896's
# own bug (all correctly guarded in the real code) -- evidence the general algorithm
# recognizes ESTABLISHED on genuinely different real shapes (a different attacker-influence
# source, a different USE pattern), not just the one function it was built against. This is
# NOT evidence of a second real vulnerability -- see RESOURCE_GUARD_R01.md's "Mining beyond
# Hermes" section for what was and was not found.
d_proxy = run("resource_guard/raw_case_hermes_proxy_call", "out_rg_proxy")
ck("real code (JSCallableProxy.cpp, era-matched 82f0f971): a different real call site, "
   "size from callerFrame.getArgCount() (not a JSArray length), use via "
   "std::uninitialized_copy_n (not a manual loop) -> RESOURCE_GUARD_ESTABLISHED",
   verdict(d_proxy) == "RESOURCE_GUARD_ESTABLISHED")

d_regexp = run("resource_guard/raw_case_hermes_regexp_replace", "out_rg_regexp")
ck("real code (RegExp.cpp, era-matched 82f0f971): a different real call site, size is a "
   "COMPUTED EXPRESSION (1 + nCaptures + 2, attacker-influenced via the regex's own "
   "capture-group count) not a bare identifier, use via a for-loop over capture groups "
   "-> RESOURCE_GUARD_ESTABLISHED, with the attacker-influence trace correctly following "
   "the arithmetic expression to the real `nCaptures` parameter",
   verdict(d_regexp) == "RESOURCE_GUARD_ESTABLISHED"
   and d_regexp["findings"][0].get("attacker_influence_evidence", {}).get("traced_to_parameter") == "nCaptures")

print(f"RESOURCE_GUARD_R01_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
