#!/usr/bin/env python3
"""SERIALIZE-DOS-R03 control gate.

Two fixture groups, per instruction ("use motifer and all existing fixtures as
development regressions"):

  1. R01's 7 fixtures (fixtures/raw/), re-run through the CORRECTED
     setup_candidate_multisource.sc pipeline (study/r03_fixtures/<pkg>/evidence_final.json).
     Expected results are IDENTICAL to R02's -- none of these fixtures had a
     first-occurrence bug, so this proves the correction is a safe, non-regressing
     drop-in for every previously-passing case.
  2. The real motifer@26.1.1 package (study/blind_motifer/raw/,
     study/r03_fixtures/index.js/evidence_final.json -- package name is literally
     "index.js" per this reducer's own _pkg() convention, since motifer's finding is a
     single top-level file). THIS is the case that changes: under R02's coordinator
     (fed by the OLD setup_candidate.sc), the automated size-axis result would have
     been SAFE_NO_STRUCTURAL_FLOW (the taint engine's false NO_FLOW). Under R03 (fed by
     the corrected multisource pipeline), it is CANDIDATE_UNBOUNDED_SERIALIZE_SIZE --
     the real, automatically-reproduced ESTABLISHED disposition. crash_dos_classification
     is unchanged (CANDIDATE_UNGUARDED_SERIALIZE_DOS, automated) -- the crash-safety
     analyzer was not touched by this correction; its real manual adjudication
     (REJECTED, an Express dispatch boundary) lives only in
     study/blind_motifer_review/MOTIFER_MANUAL_REVIEW.md, never in this gate's
     automated expectation.

  T1-T6  R01's 7 fixtures reproduce R02's exact results (T7 = sd-nonattacker,
         taint engine never consulted, unchanged).
  T8     motifer: crash CANDIDATE_UNGUARDED_SERIALIZE_DOS (automated, unchanged),
         size CANDIDATE_UNBOUNDED_SERIALIZE_SIZE sourced from a REAL
         RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS disposition -- the corrected result,
         proving R03 changes the canonical evidence relative to what R02's coordinator
         would have automatically produced.
  T9     every finding still carries reportable=false.
  T10    no vulnerability language in the output (claims-boundary lint).
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from serialize_dos_r03 import derive  # noqa: E402

raw = HERE / "fixtures" / "raw"
taint_dir = HERE / "study" / "r03_fixtures"
result = derive(raw, taint_dir)
F = result["findings"]
by = {f["package"]: f for f in F}
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def check(name, pkg, crash, size, taint_disp):
    f = by.get(pkg)
    ok = (f is not None and f["crash_dos_classification"] == crash
          and f["size_structure_dos_classification"] == size
          and f["size_structure_taint_engine_disposition"] == taint_disp)
    detail = str(f and (f["crash_dos_classification"], f["size_structure_dos_classification"],
                         f["size_structure_taint_engine_disposition"]))
    tooth(name, ok, detail)


check("T1 sd-crash-vuln (unregressed from R02)", "sd-crash-vuln",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("T2 sd-hapi (unregressed from R02)", "sd-hapi",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("T3 sd-crash-trycatch (unregressed from R02)", "sd-crash-trycatch",
      "SAFE_TRY_CATCH", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("T4 sd-crash-depthguard (unregressed from R02)", "sd-crash-depthguard",
      "SAFE_DEPTH_GUARDED", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("T5 sd-hashandler (unregressed from R02)", "sd-hashandler",
      "SUSPICIOUS_UNGUARDED_SERIALIZE", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("T6 sd-transform-present (unregressed from R02)", "sd-transform-present",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "ABSTAIN_TAINT_ENGINE_OPEN", "CANDIDATE_OPEN")

nonattacker = by.get("sd-nonattacker")
tooth("T7 sd-nonattacker: both SAFE, taint engine never consulted (unchanged from R02)",
      nonattacker is not None
      and nonattacker["crash_dos_classification"] == "SAFE_NOT_ATTACKER_CONTROLLED"
      and nonattacker["size_structure_dos_classification"] == "SAFE_NOT_ATTACKER_CONTROLLED"
      and nonattacker["size_structure_taint_engine_disposition"] is None,
      str(nonattacker))

# motifer -- derive() a second time against its own crash facts, since fixtures/raw and
# study/blind_motifer/raw are two separate real-fact directories.
motifer_result = derive(HERE / "study" / "blind_motifer" / "raw", taint_dir)
motifer_by = {f["package"]: f for f in motifer_result["findings"]}
mf = motifer_by.get("index.js")
tooth("T8 motifer: crash unchanged (automated), size NOW CORRECTLY CANDIDATE (real ESTABLISHED evidence)",
      mf is not None
      and mf["crash_dos_classification"] == "CANDIDATE_UNGUARDED_SERIALIZE_DOS"
      and mf["size_structure_dos_classification"] == "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE"
      and mf["size_structure_taint_engine_disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      str(mf and (mf["crash_dos_classification"], mf["size_structure_dos_classification"],
                  mf["size_structure_taint_engine_disposition"])))

all_findings = F + motifer_result["findings"]
tooth("T9 every finding (both fixture groups) carries reportable=false",
      len(all_findings) > 0 and all(f["reportable"] is False for f in all_findings),
      str([f["reportable"] for f in all_findings]))

blob = json.dumps(result).lower() + json.dumps(motifer_result).lower()
tooth("T10 no vulnerability language in the output (claims-boundary lint)",
      "vulnerab" not in blob, "")

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"SERIALIZE_DOS_R03={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
