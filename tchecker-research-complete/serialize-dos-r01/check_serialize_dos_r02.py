#!/usr/bin/env python3
"""SERIALIZE-DOS-R02 control gate.

Reuses R01's real-Joern-compiled crash-DoS facts (fixtures/raw/) unchanged. Adds real
taint-engine evidence_final.json files (study/r02_fixtures/<package>/), each produced
by an independent, per-package jssrc2cpg compile through the REAL, unmodified
setup_candidate.sc -> export_property_propagation.sc -> export_trace_identity.sc ->
adjudicate_js.py pipeline (never approximated or reimplemented).

  R1 sd-crash-vuln        -> crash CANDIDATE_UNGUARDED_SERIALIZE_DOS,
                              size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE (taint engine: RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS)
  R2 sd-hapi               -> same shape, request.payload source pattern
  R3 sd-crash-trycatch     -> crash SAFE_TRY_CATCH,
                              size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE (axes disagree, taint-engine-confirmed)
  R4 sd-crash-depthguard   -> crash SAFE_DEPTH_GUARDED,
                              size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE (axes disagree, taint-engine-confirmed)
  R5 sd-hashandler         -> crash SUSPICIOUS_UNGUARDED_SERIALIZE,
                              size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE (axes disagree, taint-engine-confirmed)
  R6 sd-transform-present  -> crash CANDIDATE_UNGUARDED_SERIALIZE_DOS,
                              size  ABSTAIN_TAINT_ENGINE_OPEN (real taint engine: CANDIDATE_OPEN, not R01's
                                    own approximation -- this is the architectural correction under test)
  R7 sd-nonattacker        -> both axes SAFE_NOT_ATTACKER_CONTROLLED, taint engine never consulted
                              (no evidence_final.json exists for this package -- proves the coordinator
                              correctly skips the expensive engine when crash facts already settle it)
  R8  every finding carries reportable=false
  R9  size_structure_taint_engine_disposition is the raw string from the real evidence_final.json,
      never a value this module invented
  R10 the structural pre-filter is present but clearly separate from the classification (R01's old
      approximation is demoted, not silently reused as the verdict)
  R11 no vulnerability language in the output (claims-boundary lint)
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from serialize_dos_r02 import derive  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "raw"
taint_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "study" / "r02_fixtures"
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


check("R1 sd-crash-vuln", "sd-crash-vuln",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("R2 sd-hapi", "sd-hapi",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("R3 sd-crash-trycatch (axes disagree, taint-engine-confirmed)", "sd-crash-trycatch",
      "SAFE_TRY_CATCH", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("R4 sd-crash-depthguard (axes disagree, taint-engine-confirmed)", "sd-crash-depthguard",
      "SAFE_DEPTH_GUARDED", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("R5 sd-hashandler (axes disagree, taint-engine-confirmed)", "sd-hashandler",
      "SUSPICIOUS_UNGUARDED_SERIALIZE", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
      "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("R6 sd-transform-present (real taint engine says OPEN, not R01's own guess)", "sd-transform-present",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "ABSTAIN_TAINT_ENGINE_OPEN", "CANDIDATE_OPEN")

nonattacker = by.get("sd-nonattacker")
tooth("R7 sd-nonattacker: both SAFE, taint engine never consulted (no evidence file exists for it)",
      nonattacker is not None
      and nonattacker["crash_dos_classification"] == "SAFE_NOT_ATTACKER_CONTROLLED"
      and nonattacker["size_structure_dos_classification"] == "SAFE_NOT_ATTACKER_CONTROLLED"
      and nonattacker["size_structure_taint_engine_disposition"] is None
      and nonattacker["size_structure_taint_engine_evidence_path"] is None
      and not (taint_dir / "sd-nonattacker" / "evidence_final.json").exists(),
      str(nonattacker))

tooth("R8 every finding carries reportable=false",
      len(F) > 0 and all(f["reportable"] is False for f in F),
      str([f["reportable"] for f in F]))

vuln = by.get("sd-crash-vuln")
tooth("R9 taint engine disposition is the raw evidence string, not invented",
      vuln is not None and vuln["size_structure_taint_engine_disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS"
      and vuln["size_structure_taint_engine_evidence_path"] is not None
      and vuln["size_structure_taint_engine_evidence_path"].endswith("evidence_final.json"),
      str(vuln and vuln["size_structure_taint_engine_disposition"]))

tp = by.get("sd-transform-present")
tooth("R10 structural pre-filter present but separate from the classification",
      tp is not None
      and tp["size_structure_structural_prefilter"] == "PREFILTER_TRANSFORM_PRESENT_RUN_TAINT_ENGINE"
      and tp["size_structure_dos_classification"] != tp["size_structure_structural_prefilter"],
      str(tp and (tp["size_structure_structural_prefilter"], tp["size_structure_dos_classification"])))

blob = json.dumps(result).lower()
tooth("R11 no vulnerability language in the output (claims-boundary lint)",
      "vulnerab" not in blob, "")

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"SERIALIZE_DOS_R02={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
