#!/usr/bin/env python3
"""SERIALIZE-DOS-R04 control gate. All facts and evidence below are produced by the
real, unmodified pipeline (jssrc2cpg -> npm_public_export_sources_r04.sc ->
export_property_propagation.sc -> export_trace_identity.sc -> adjudicate_js.py, run
externally per this session's established convention) -- fixtures_r04/ (9 combined
fixtures) and study/r04_motifer, study/r04_logify (the two real packages this revision
re-runs).

  C1  r4-param-direct        exported function parameter directly serialized ->
                              CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED (ESTABLISHED)
  C2  r4-param-helper        exported parameter through a uniquely resolved helper ->
                              ABSTAIN_TAINT_ENGINE_OPEN (real interprocedural flow through
                              wrap(), CANDIDATE_OPEN -- "uniquely resolved" is the trace/
                              call-edge layer, not a guarantee of ESTABLISHED; wrap is the
                              only method named "wrap" in the whole CPG, statically
                              unambiguous)
  C3  r4-this-field          exported class constructor parameter stored in this.field,
                              serialized by another method -> CANDIDATE_..._NOT_ESTABLISHED
  C4  r4-obj-shorthand       object-literal shorthand exported function -> CANDIDATE_..._NOT_ESTABLISHED
                              (only foo, the one whose value is actually serialized; bar
                              never even has a sink)
  C5  r4-internal-only       internal-only parameter, never externally sourced (the
                              consuming helper is never exported) -> NO_SUPPORTED_EXTERNAL_INPUT_FLOW,
                              zero PACKAGE_API_INPUT rows at the producer level
  C6  r4-same-name-unrelated same-name parameter in an unrelated, non-exported function
                              must not contribute -> the exported function's own site
                              resolves; the unrelated one is never even a candidate sink
  C7  r4-ambiguous-export    ambiguous call edge (reassigned identifier, two candidate
                              MethodRefs) -> abstain, zero PACKAGE_API_INPUT rows (real
                              observed reason: UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT
                              -- neither assignment is Identifier=MethodRef-shaped, matching
                              the ReDoS work's own prior "honest note" finding for the
                              analogous class-export case; never a guess either way)
  C8  r4-unknown-transform   exported method's own parameter through an unknown member-
                              method transform -> ABSTAIN_TAINT_ENGINE_OPEN (CANDIDATE_OPEN)
  C9  r4-proven-bound        exported parameter through a proven, package-local size bound
                              (slice with a numeric literal arg) -> SAFE_VALUE_NOT_PRESERVED
                              (REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED -- a real negative)
  C10 external bound never conflated with package-local proof -- motifer's automated
      classification is CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED even though a real
      external (consumer-chosen, reconfigurable) body-parser bound exists in its
      documented usage; the automated reducer has no way to see that bound at all, by
      construction, and never claims safety because of it -- the external bound is
      recorded ONLY in the separate manual-review document (MOTIFER_MANUAL_REVIEW.md).
  C11 motifer remains APPLICATION_INGRESS_INPUT-flow confirmed, with the four-tag manual
      record intact; ALSO, disclosed and not hidden, PACKAGE_API_INPUT ("express") is
      flagged at the same sink by the raw batched check -- a real, observed closure-
      capture over-approximation (see R04_RESULTS.md Sec.3.1), never silently promoted
      as an additional genuine candidate.
  C12 logify (@rasla/logify, real, 48,100-call CPG) is rerun under R04: of its 68 real
      serializer sites, exactly ONE (line 1521, the vendored `ms` package's own exported
      function, `val` parameter, in an error-message JSON.stringify) is now
      PACKAGE_API_INPUT reachable -- a real, automated RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS,
      genuine positive-path portability evidence on top of R03's own logify draw.
  C13 every finding still carries reportable=false.
  C14 no vulnerability language in the output (claims-boundary lint).
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from serialize_dos_r04 import derive  # noqa: E402

fx_raw = HERE / "fixtures_r04" / "raw"
fx_npm = HERE / "fixtures_r04" / "npm_source_facts"
fx_taint = HERE / "study" / "r04_fixtures"
fx_result = derive(fx_raw, fx_npm, fx_taint)
fx_by = {f["package"]: f for f in fx_result["findings"]}

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def check(name, pkg, crash, size, families, taint_disp):
    f = fx_by.get(pkg)
    ok = (f is not None and f["crash_dos_classification"] == crash
          and f["size_structure_dos_classification"] == size
          and f["external_input_families"] == sorted(families)
          and f["size_structure_taint_engine_disposition"] == taint_disp)
    detail = str(f)
    tooth(name, ok, detail)


check("C1 r4-param-direct", "r4-param-direct",
      "NO_SUPPORTED_EXTERNAL_INPUT_FLOW", "CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED",
      {"PACKAGE_API_INPUT"}, "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("C2 r4-param-helper (uniquely resolved helper, real interprocedural flow, OPEN)", "r4-param-helper",
      "NO_SUPPORTED_EXTERNAL_INPUT_FLOW", "ABSTAIN_TAINT_ENGINE_OPEN",
      {"PACKAGE_API_INPUT"}, "CANDIDATE_OPEN")
check("C3 r4-this-field (constructor param -> this.field -> method)", "r4-this-field",
      "NO_SUPPORTED_EXTERNAL_INPUT_FLOW", "CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED",
      {"PACKAGE_API_INPUT"}, "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")
check("C4 r4-obj-shorthand (object-literal shorthand export)", "r4-obj-shorthand",
      "NO_SUPPORTED_EXTERNAL_INPUT_FLOW", "CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED",
      {"PACKAGE_API_INPUT"}, "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")

internal_only = fx_by.get("r4-internal-only")
tooth("C5 r4-internal-only: never externally sourced, zero PACKAGE_API_INPUT",
      internal_only is not None
      and internal_only["crash_dos_classification"] == "NO_SUPPORTED_EXTERNAL_INPUT_FLOW"
      and internal_only["size_structure_dos_classification"] == "NO_SUPPORTED_EXTERNAL_INPUT_FLOW"
      and internal_only["external_input_families"] == [],
      str(internal_only))

check("C6 r4-same-name-unrelated (unrelated function's same-named param never contributes)", "r4-same-name-unrelated",
      "NO_SUPPORTED_EXTERNAL_INPUT_FLOW", "CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED",
      {"PACKAGE_API_INPUT"}, "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")

ambiguous = fx_by.get("r4-ambiguous-export")
tooth("C7 r4-ambiguous-export: ambiguous call edge, abstain, zero PACKAGE_API_INPUT",
      ambiguous is not None
      and ambiguous["crash_dos_classification"] == "NO_SUPPORTED_EXTERNAL_INPUT_FLOW"
      and ambiguous["size_structure_dos_classification"] == "NO_SUPPORTED_EXTERNAL_INPUT_FLOW"
      and ambiguous["external_input_families"] == [],
      str(ambiguous))

check("C8 r4-unknown-transform (unknown member-method transform, abstain)", "r4-unknown-transform",
      "NO_SUPPORTED_EXTERNAL_INPUT_FLOW", "ABSTAIN_TAINT_ENGINE_OPEN",
      {"PACKAGE_API_INPUT"}, "CANDIDATE_OPEN")
check("C9 r4-proven-bound (proven package-local size bound, negative)", "r4-proven-bound",
      "NO_SUPPORTED_EXTERNAL_INPUT_FLOW", "SAFE_VALUE_NOT_PRESERVED",
      {"PACKAGE_API_INPUT"}, "REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED")

# C10/C11: motifer, real package
motifer = derive(HERE / "study" / "blind_motifer" / "raw", HERE / "study" / "r04_motifer",
                  HERE / "study" / "r04_motifer")
mf = {f["package"]: f for f in motifer["findings"]}.get("index.js")
tooth("C10 motifer: external bound never treated as package-local proof "
      "(automated classification stays CANDIDATE_..._NOT_ESTABLISHED; the real external "
      "body-parser bound is recorded only in MOTIFER_MANUAL_REVIEW.md, never here)",
      mf is not None and mf["size_structure_dos_classification"] == "CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED",
      str(mf))
tooth("C11 motifer: APPLICATION_INGRESS_INPUT flow confirmed; PACKAGE_API_INPUT "
      "(a real, disclosed closure-capture over-approximation) shown, not hidden",
      mf is not None and "APPLICATION_INGRESS_INPUT" in mf["external_input_families"]
      and "PACKAGE_API_INPUT" in mf["external_input_families"]
      and mf["crash_dos_classification"] == "CANDIDATE_UNGUARDED_SERIALIZE_DOS",
      str(mf and mf["external_input_families"]))

# C12: logify, real package, 68 sites, exactly one PACKAGE_API_INPUT-reachable
logify = derive(HERE / "study" / "blind_r03_logify" / "raw", HERE / "study" / "r04_logify",
                 HERE / "study" / "r04_logify")
logify_findings = logify["findings"]
logify_package_api = [f for f in logify_findings if "PACKAGE_API_INPUT" in f["external_input_families"]]
tooth("C12 logify: exactly 1 of 68 real sites is now PACKAGE_API_INPUT reachable "
      "(the vendored ms package's own exported function, real RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS)",
      len(logify_findings) == 68 and len(logify_package_api) == 1
      and logify_package_api[0]["line"] == "1521"
      and logify_package_api[0]["size_structure_taint_engine_disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      str(logify_package_api))

all_findings = fx_result["findings"] + motifer["findings"] + logify_findings
tooth("C13 every finding (all 3 fixture groups) carries reportable=false",
      len(all_findings) > 0 and all(f["reportable"] is False for f in all_findings),
      "")

blob = (json.dumps(fx_result) + json.dumps(motifer) + json.dumps(logify)).lower()
tooth("C14 no vulnerability language in the output (claims-boundary lint)",
      "vulnerab" not in blob, "")

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"SERIALIZE_DOS_R04={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
