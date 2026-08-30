#!/usr/bin/env python3
"""RESOURCE-GUARD-R04 validation gate. Two parts, run BEFORE freezing R04 (see
RESOURCE_GUARD_R04.md's "Freeze" section for the recorded hash):

1. The 6 required build-configuration-applicability controls, run against ALREADY-COMMITTED
   real Joern facts (R03's own `raw_r03a_napi_buffer_matches`, unguarded, plus one NEW real
   fixture -- `raw_r04c02_disabled_correct_guard`, correctly guarded -- both under
   study/resource_guard_r04/), varying only the `build_config.json` evidence supplied via
   `--build-config`. Build-configuration resolution is independent of the CPG facts
   entirely (Joern carries no preprocessor state -- established repeatedly since R02), so
   these controls exercise the NEW gate purely by varying that one external input, reusing
   real fixture facts rather than requiring 6 new Joern runs.

2. The two named development/regression cases (per explicit instruction): jpeg-turbo,
   using its own REAL build-configuration evidence (independently re-verified: no
   NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS anywhere in its real CMakeLists.txt, and
   node-addon-api's own real default-resolution logic) -- R04 must reject the R03 finding as
   NOT APPLICABLE; and Cartesi, using ITS real build-configuration evidence (explicit
   NAPI_DISABLE_CPP_EXCEPTIONS in its real binding.gyp) -- R04 must still evaluate and report
   the missing-guard property there, exactly as R03 (correctly) did.

Every fixture here is real Joern v4.0.608 output -- no synthetic JSON facts. R03's own study
directories (study/resource_guard_r02/, study/resource_guard_r03/) are READ but never
modified by this gate or by any file R04 touches.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "resource_guard_verdict_r04.py"
STUDY_R02 = HERE / "study" / "resource_guard_r02"
STUDY_R03 = HERE / "study" / "resource_guard_r03"
STUDY_R04 = HERE / "study" / "resource_guard_r04"
BC = STUDY_R04 / "build_configs"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(rawdir, outname, build_config=None, real=True):
    outpath = HERE / (outname + ".json")
    cmd = [sys.executable, str(CAP), str(rawdir), str(outpath)]
    if real:
        cmd.append("--real")
    if build_config:
        cmd += ["--build-config", str(build_config)]
    subprocess.run(cmd, check=True)
    return json.loads(outpath.read_text())


def verdicts(d):
    return sorted(f["verdict"] for f in d["findings"])


# ---------------------------------------------------------------------------
# 1. The 6 required build-configuration-applicability controls.
# ---------------------------------------------------------------------------
UNGUARDED = STUDY_R03 / "raw_r03a_napi_buffer_matches"
GUARDED = STUDY_R04 / "raw_r04c02_disabled_correct_guard"

d1 = run(UNGUARDED, "out_r04_c1", build_config=BC / "bc_disabled.json")
ck("control 1: NAPI_DISABLE_CPP_EXCEPTIONS established + missing guard -> "
   "VALUE_ACQUISITION_GUARD_MISSING", verdicts(d1) == ["VALUE_ACQUISITION_GUARD_MISSING"])

d2 = run(GUARDED, "out_r04_c2", build_config=BC / "bc_disabled.json")
ck("control 2: NAPI_DISABLE_CPP_EXCEPTIONS established + correct guard -> "
   "VALUE_ACQUISITION_GUARD_ESTABLISHED", verdicts(d2) == ["VALUE_ACQUISITION_GUARD_ESTABLISHED"])

d3 = run(UNGUARDED, "out_r04_c3", build_config=BC / "bc_enabled.json")
ck("control 3: exceptions established enabled + missing IsEmpty -> CONTRACT_NOT_APPLICABLE "
   "(reason ACQUISITION_FAILURE_THROWS)",
   verdicts(d3) == ["CONTRACT_NOT_APPLICABLE"]
   and d3["findings"][0]["reason"] == "ACQUISITION_FAILURE_THROWS"
   and d3["findings"][0]["r03_would_be_verdict"] == "VALUE_ACQUISITION_GUARD_MISSING")

d4 = run(UNGUARDED, "out_r04_c4", build_config=BC / "bc_unresolved.json")
ck("control 4: exception mode unresolved -> BUILD_CONFIGURATION_UNRESOLVED",
   verdicts(d4) == ["BUILD_CONFIGURATION_UNRESOLVED"])

d4b = run(UNGUARDED, "out_r04_c4b", build_config=None)
ck("control 4b: no build_config.json supplied at all (neither --build-config nor "
   "RAW_DIR/build_config.json) -> BUILD_CONFIGURATION_UNRESOLVED, never defaulted to "
   "'disabled'", verdicts(d4b) == ["BUILD_CONFIGURATION_UNRESOLVED"])

d5 = run(UNGUARDED, "out_r04_c5", build_config=BC / "bc_conflict.json")
ck("control 5: conflicting build definitions (both NAPI_CPP_EXCEPTIONS and "
   "NAPI_DISABLE_CPP_EXCEPTIONS present) -> BUILD_CONFIGURATION_CONFLICT",
   verdicts(d5) == ["BUILD_CONFIGURATION_CONFLICT"])

d6 = run(UNGUARDED, "out_r04_c6", build_config=BC / "bc_unrelated.json")
ck("control 6: an unrelated exception-sounding flag (no bearing on NAPI_CPP_EXCEPTIONS/"
   "NAPI_DISABLE_CPP_EXCEPTIONS) -> no applicability evidence established, resolves to "
   "BUILD_CONFIGURATION_UNRESOLVED, not silently treated as real evidence",
   verdicts(d6) == ["BUILD_CONFIGURATION_UNRESOLVED"])

# ---------------------------------------------------------------------------
# 2. Named development/regression cases.
# ---------------------------------------------------------------------------
d_jpegturbo = run(STUDY_R03 / "raw_case_jpegturbo_decompress", "out_r04_jpegturbo",
                   build_config=BC / "bc_jpegturbo_enabled.json")
ck("jpeg-turbo (R04 development/regression case): R03's own real facts, gated through R04's "
   "REAL build-configuration evidence (exceptions most likely enabled -- CMakeLists.txt has "
   "neither macro, node-addon-api's own default-resolution logic enables exceptions absent "
   "an explicit opt-out) -> CONTRACT_NOT_APPLICABLE, correctly REJECTING R03's own "
   "VALUE_ACQUISITION_GUARD_MISSING finding as not applicable, not rewriting it",
   verdicts(d_jpegturbo) == ["CONTRACT_NOT_APPLICABLE"]
   and d_jpegturbo["findings"][0]["r03_would_be_verdict"] == "VALUE_ACQUISITION_GUARD_MISSING")

d_cartesi = run(STUDY_R02 / "raw_case_cartesi_readmemory", "out_r04_cartesi",
                 build_config=BC / "bc_cartesi_disabled.json")
ck("Cartesi (opposite development case): real facts, gated through R04's REAL "
   "build-configuration evidence (NAPI_DISABLE_CPP_EXCEPTIONS explicitly defined in the "
   "real binding.gyp) -> the missing-guard property IS evaluated and correctly fires, "
   "VALUE_ACQUISITION_GUARD_MISSING, matching R03's own recovery result exactly",
   verdicts(d_cartesi) == ["VALUE_ACQUISITION_GUARD_MISSING"])

# ---------------------------------------------------------------------------
# Cross-cutting: none of the new applicability categories carries a cwe_hint or a
# vulnerability claim; every one explicitly disclaims one in its own evidence_note.
# ---------------------------------------------------------------------------
all_findings = []
for d in (d1, d2, d3, d4, d4b, d5, d6, d_jpegturbo, d_cartesi):
    all_findings.extend(d["findings"])
ck("no finding anywhere carries a cwe_hint/capacity claim",
   all("cwe_hint" not in f for f in all_findings))
ck("every CONTRACT_NOT_APPLICABLE finding explicitly disclaims a vulnerability/CWE-787/"
   "exploit claim in its own evidence_note",
   all(("not a vulnerability claim" in f.get("evidence_note", "").lower()
        and "CWE-787" in f.get("evidence_note", ""))
       for f in all_findings if f["verdict"] == "CONTRACT_NOT_APPLICABLE"))
ck("every BUILD_CONFIGURATION_UNRESOLVED/CONFLICT finding states it is an abstention, "
   "never a default",
   all("abstention" in f.get("evidence_note", "").lower()
       or "never" in f.get("evidence_note", "").lower()
       for f in all_findings
       if f["verdict"] in ("BUILD_CONFIGURATION_UNRESOLVED", "BUILD_CONFIGURATION_CONFLICT")))

print(f"RESOURCE_GUARD_R04_GATE={ok}/{total}")
sys.exit(0 if ok == total else 1)
