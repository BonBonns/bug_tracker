#!/usr/bin/env python3
"""RESOURCE-GUARD-R03 validation gate. Three parts, all against real Joern v4.0.608 output,
run BEFORE freezing R03 (see RESOURCE_GUARD_R03.md's "Freeze" section for the recorded hash):

1. PARITY: R02's own 16 original synthetic-control fixtures (study/resource_guard_r02/
   raw_r02c*, unchanged, no new Joern runs needed), re-run through R03's algorithm +
   contracts. Since R03's algorithm is a byte-for-byte copy of R02's (see
   resource_guard_verdict_r03.py's own module docstring) and R03's SYNTHETIC_CONTRACTS
   carries R02's two original entries unchanged, every verdict here must reproduce R02's own
   recorded expectation exactly -- proving this correction touched nothing beyond the one
   documented field (REAL_CONTRACTS["Napi::Buffer"]["qualifier_type"]).

2. NAMESPACE-DISCRIMINATION controls (5 required behaviors, 4 new real fixtures under
   study/resource_guard_r03/): a correctly-namespaced Napi::Buffer::New call MATCHES; a
   same-named call under an unrelated namespace does NOT match; an unqualified/unnamespaced
   Buffer::New call matches ONLY its own, explicitly separate synthetic contract (never the
   real one, and vice versa); a call whose methodFullName the c2cpg frontend never resolves
   at all (reusing node-canvas's own already-committed real facts) still ABSTAINS; and a
   lookalike class name of identical method-name/arity but the WRONG canonical form (no
   namespace separator) does NOT match -- the last two specifically guard against a loose
   suffix/substring qualifier check, which this project's exact-prefix `str.startswith()`
   check was never at risk of, but which these controls now prove empirically rather than by
   code-reading alone.

3. CARTESI POST-FIX RECOVERY (study/resource_guard_r02/raw_case_cartesi_readmemory -- REAL,
   already-committed Joern facts, not re-run through Joern here): this is explicitly NOT a
   blind test and NOT a retroactive rewrite of R02's own recorded result (which stands,
   unmodified, in RESOURCE_GUARD_R02.md). Cartesi is now an R03 DEVELOPMENT/REGRESSION case,
   because its own R02 result is exactly what motivated this correction. Verified here:
   VALUE_ACQUISITION_GUARD_MISSING fires, with field-level assertions for the evidence this
   contract can automatically attach (object identity, exceptions-disabled assumption,
   downstream use before any failure check, no dominating guard) -- and an explicit,
   documented note on the ONE piece of required evidence this run does NOT automatically
   attach (attacker-influence trace on `length`), because `length` is populated through an
   out-parameter call (`get_u64(env, info[1], "length", &length)`), a data-flow pattern
   `backward_attacker_trace` was never designed to follow (it follows `lhs = rhs` assignment
   chains only) -- NOT fixed here, per the explicit instruction not to touch attacker
   tracing; the underlying fact (JS-controlled length, bounded only by SIZE_MAX) was
   independently verified from the real source in RESOURCE_GUARD_R02.md's Blind test #2 and
   is NOT re-derived by this gate.

Per explicit instruction: a VALUE_ACQUISITION_GUARD_MISSING finding, including Cartesi's own,
is a missing-guard finding under this contract's own disclosed assumptions -- it is NOT
automatically a vulnerability, NOT automatically CWE-787, and NOT proof of exploitable
memory corruption. This gate asserts the finding's own evidence_note says exactly that.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "resource_guard_verdict_r03.py"
STUDY_R02 = HERE / "study" / "resource_guard_r02"
STUDY_R03 = HERE / "study" / "resource_guard_r03"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(rawdir, outname, real=False):
    outpath = HERE / (outname + ".json")
    cmd = [sys.executable, str(CAP), str(rawdir), str(outpath)]
    if real:
        cmd.append("--real")
    subprocess.run(cmd, check=True)
    return json.loads(outpath.read_text())


def verdicts(d):
    return sorted(f["verdict"] for f in d["findings"])


# ---------------------------------------------------------------------------
# 1. PARITY: R02's own 16 original controls, re-run through R03 unchanged.
# ---------------------------------------------------------------------------
PARITY_CONTROLS = [
    ("raw_r02c01_missing_guard", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c02_correct_guard", ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
    ("raw_r02c03_inverted_predicate", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c04_check_after_use", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c05_check_different_object", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c06_called_twice_one_checked",
     ["VALUE_ACQUISITION_GUARD_ESTABLISHED", "VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c07_result_aliased", ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
    ("raw_r02c08_non_dominating_guard", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c09_nonterminating_failure_branch", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c10_exceptions_enabled_try_catch", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c11_exceptions_disabled_loop_shaped", ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
    ("raw_r02c12_unrelated_class", ["VALUE_ACQUISITION_GUARD_MISSING"]),
    ("raw_r02c13_no_size_argument", ["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"]),
    ("raw_r02c15_unresolved_temporary_result", ["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"]),
    ("raw_r02c16_instance_factory", ["VALUE_ACQUISITION_GUARD_ESTABLISHED"]),
]
for rawdir, expected in PARITY_CONTROLS:
    d = run(STUDY_R02 / rawdir, f"out_r03parity_{rawdir}")
    ck(f"parity: {rawdir} -> {expected} (R02's own SYNTHETIC controls, unchanged by R03)",
       verdicts(d) == sorted(expected))

d14 = run(STUDY_R02 / "raw_r02c14_zero_length_valid", "out_r03parity_c14")
ck("parity: attacker-independent literal size -- ZERO findings, SIZE_ATTACKER_INDEPENDENT",
   d14["findings"] == [] and d14["classification"].get("SIZE_ATTACKER_INDEPENDENT") == 1)

d05 = run(STUDY_R02 / "raw_r02c05_check_different_object", "out_r03parity_c05_check")
ck("parity: check-on-different-object finding still names 'r', not 'g'",
   d05["findings"][0]["object"] == "r"
   and d05["classification"].get("RESOURCE_ACQUIRED_NO_USE") == 1)

d12 = run(STUDY_R02 / "raw_r02c12_unrelated_class", "out_r03parity_c12_check")
ck("parity: unrelated class still rejected via ACQUISITION_SIGNATURE_UNRECOGNIZED",
   d12["classification"].get("ACQUISITION_SIGNATURE_UNRECOGNIZED") == 1)

# ---------------------------------------------------------------------------
# 2. NAMESPACE-DISCRIMINATION controls (5 required behaviors, real Joern facts).
# ---------------------------------------------------------------------------
dA = run(STUDY_R03 / "raw_r03a_napi_buffer_matches", "out_r03a", real=True)
ck("R03A: Napi::Buffer::New -> MATCHES the corrected real contract "
   "(VALUE_ACQUISITION_GUARD_MISSING, unguarded)",
   verdicts(dA) == ["VALUE_ACQUISITION_GUARD_MISSING"])

dB = run(STUDY_R03 / "raw_r03b_other_namespace_rejected", "out_r03b", real=True)
ck("R03B: Other::Buffer::New (same method name/arity, WRONG namespace) -> does NOT match "
   "(ACQUISITION_SIGNATURE_UNRECOGNIZED, zero findings)",
   dB["findings"] == [] and dB["classification"].get("ACQUISITION_SIGNATURE_UNRECOGNIZED") == 1)

dC_synth = run(STUDY_R03 / "raw_r03c_unqualified_synthetic_buffer", "out_r03c_synth", real=False)
ck("R03C (synthetic pool): unqualified/unnamespaced Buffer::New -> matches its own, "
   "explicitly SEPARATE synthetic contract (VALUE_ACQUISITION_GUARD_MISSING)",
   verdicts(dC_synth) == ["VALUE_ACQUISITION_GUARD_MISSING"])

dC_real = run(STUDY_R03 / "raw_r03c_unqualified_synthetic_buffer", "out_r03c_real", real=True)
ck("R03C (real pool, same fixture): the SAME unqualified call does NOT match the real, "
   "namespace-qualified Napi::Buffer contract -- confirms pool separation both ways",
   dC_real["findings"] == []
   and dC_real["classification"].get("ACQUISITION_SIGNATURE_UNRECOGNIZED") == 1)

dD = run(STUDY_R02 / "raw_case_node_canvas_streampdf", "out_r03d_node_canvas", real=True)
ck("R03D: a call whose methodFullName c2cpg never resolves (real node-canvas facts, reused "
   "unchanged from R02's own blind test) -> still ABSTAINS (zero findings, "
   "ACQUISITION_SIGNATURE_UNRECOGNIZED) -- this correction does not, and should not, change "
   "node-canvas's own out-of-contract result",
   dD["findings"] == [] and dD["classification"].get("ACQUISITION_SIGNATURE_UNRECOGNIZED") == 1)

dE = run(STUDY_R03 / "raw_r03e_lookalike_class_rejected", "out_r03e", real=True)
ck("R03E: a lookalike class 'NapiBuffer' (same method name/arity, no namespace separator) "
   "-> does NOT match (ACQUISITION_SIGNATURE_UNRECOGNIZED, zero findings) -- confirms exact-"
   "prefix matching, not loose suffix/substring matching",
   dE["findings"] == [] and dE["classification"].get("ACQUISITION_SIGNATURE_UNRECOGNIZED") == 1)

# ---------------------------------------------------------------------------
# 3. CARTESI POST-FIX RECOVERY -- development/regression case, NOT a blind test, NOT a
#    rewrite of R02's own recorded (unmodified) result.
# ---------------------------------------------------------------------------
d_cartesi = run(STUDY_R02 / "raw_case_cartesi_readmemory", "out_r03_cartesi_recovery", real=True)
ck("Cartesi recovery: exactly one finding, VALUE_ACQUISITION_GUARD_MISSING",
   verdicts(d_cartesi) == ["VALUE_ACQUISITION_GUARD_MISSING"])
cartesi_finding = d_cartesi["findings"][0] if d_cartesi["findings"] else {}
ck("Cartesi recovery: two-argument allocating overload matched "
   "(ACQUISITION_CALL_FOUND=1, acquisition_kind=STATIC_FACTORY, result_type=Buffer)",
   d_cartesi["classification"].get("ACQUISITION_CALL_FOUND") == 1
   and cartesi_finding.get("acquisition_kind") == "STATIC_FACTORY"
   and cartesi_finding.get("result_type") == "Buffer")
ck("Cartesi recovery: returned object identity resolved ('data', the real LHS variable)",
   cartesi_finding.get("object") == "data")
ck("Cartesi recovery: exceptions-disabled configuration carried as a disclosed assumption",
   str(cartesi_finding.get("applicable_exception_configuration_assumed", "")
       ).startswith("exceptions_disabled"))
ck("Cartesi recovery: downstream use before any failure check evidenced "
   "(unguarded_use_call_id present) and no dominating IsEmpty()/exception-pending guard "
   "(verdict itself is GUARD_MISSING, not ESTABLISHED)",
   cartesi_finding.get("unguarded_use_call_id") is not None)
ck("Cartesi recovery: evidence_note explicitly disclaims a vulnerability/CWE-787/exploit "
   "claim (a missing guard under this contract is not, by itself, any of those)",
   "not a vulnerability claim" in cartesi_finding.get("evidence_note", "")
   and "CWE-787" in cartesi_finding.get("evidence_note", ""))
ck("Cartesi recovery: JS-controlled length is NOT automatically evidenced by this run's own "
   "attacker_influence_evidence field -- a real, disclosed limitation (see module docstring: "
   "`length` is set via an out-parameter call, get_u64(..., &length), a pattern "
   "backward_attacker_trace was never designed to follow), NOT fixed here; the underlying "
   "fact was independently verified from real source in RESOURCE_GUARD_R02.md instead",
   "attacker_influence_evidence" not in cartesi_finding)

# ---------------------------------------------------------------------------
# Cross-cutting: property-classification discipline holds across every fixture run above.
# ---------------------------------------------------------------------------
all_findings = []
for d in (dA, dB, dC_synth, dC_real, dD, dE, d_cartesi, d05, d12, d14):
    all_findings.extend(d["findings"])
for rawdir, _expected in PARITY_CONTROLS:
    all_findings.extend(json.loads((HERE / f"out_r03parity_{rawdir}.json").read_text())["findings"])

ck("no finding anywhere carries a cwe_hint/capacity claim",
   all("cwe_hint" not in f for f in all_findings))
ck("every VALUE_ACQUISITION_GUARD_MISSING finding discloses its "
   "applicable_exception_configuration_assumed and evidence_note explicitly",
   all(("applicable_exception_configuration_assumed" in f and "evidence_note" in f)
       for f in all_findings if f["verdict"] == "VALUE_ACQUISITION_GUARD_MISSING"))

print(f"RESOURCE_GUARD_R03_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
