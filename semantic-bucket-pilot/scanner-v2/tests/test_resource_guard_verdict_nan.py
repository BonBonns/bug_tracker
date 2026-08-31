#!/usr/bin/env python3
"""NAN CAPABILITY: regression for resource_guard_verdict_nan.py, run against the REAL raw
facts committed in study/nan_capability/controls/comprehensive_fixture/ (produced by an
actual c2cpg/jssrc2cpg run over pkg/ -- see that fixture's own build_fixture.sh to reproduce).

Nine real, purpose-built cases, each isolating exactly one contract-boundary decision:

  ReadAreaLike          -- POSITIVE: JS-argument-controlled (product of two info[] reads,
                           matching node-snap7's own real ReadArea shape), no bound check.
  UploadLike            -- POSITIVE: 2-arg NewBuffer(data,size) overload, single info[] source.
  GuardedLike            -- NEGATIVE: JS-argument-controlled, but an explicit `size > 65536`
                           check dominates -- must NOT be reported unbounded.
  InternalConstantLike   -- NEGATIVE: fixed literal size, contract not applicable.
  NotRegisteredLike      -- NEGATIVE: real info[N] chain, but never registered -- not JS-
                           reachable.
  TopLevelLike           -- NEGATIVE: really registered (Nan::SetMethod), but no real JS call
                           reaches it in this fixture -- JS_CALL_UNRESOLVED, not a guess.
  CopyGoodLike           -- NEGATIVE: source capacity and copy length are the SAME identifier
                           (`new char[size]` then `CopyBuffer(data, size)`) -- capacity
                           established safe by construction, must NOT be promoted.
  CopyMismatchLike       -- POSITIVE: a real local allocation of a FIXED 128 bytes, copied with
                           an independent JS-controlled length -- genuine structural mismatch.
  CopyUnresolvedLike     -- NEGATIVE: source is an opaque struct/map field (no local
                           allocation site at all, matching node-snap7's own real server-side
                           shape) -- must emit UNRESOLVED, never an inferred OOB read.

Run: python3 tests/test_resource_guard_verdict_nan.py   (exit 0 = PASS)
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(ROOT, "study", "nan_capability", "controls", "comprehensive_fixture")
CPP_RAW = os.path.join(FIXTURE, "cpp_raw")
JS_RAW = os.path.join(FIXTURE, "js_raw")

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if cond:
        passed += 1
    else:
        failed += 1


def main():
    out_path = "/tmp/test_nan_verdict_out.json"
    subprocess.run([sys.executable, os.path.join(ROOT, "resource_guard_verdict_nan.py"),
                    CPP_RAW, JS_RAW, out_path], check=True, cwd=ROOT)
    doc = json.load(open(out_path))
    findings_by_method = {f["method_name"]: f for f in doc["findings"]}
    cls = doc["classification"]

    # --- registration extraction -----------------------------------------------------------
    check("all 8 fixture methods registered",
          set(doc["registrations"].keys()) == {
              "readAreaLike", "uploadLike", "guardedLike", "internalConstantLike",
              "copyGoodLike", "copyMismatchLike", "copyUnresolvedLike", "topLevelLike"},
          str(doc["registrations"].keys()))

    # --- NewBuffer contract ------------------------------------------------------------------
    check("ReadAreaLike -> NAN_NEWBUFFER_UNBOUNDED_ALLOCATION (positive)",
          findings_by_method.get("ReadAreaLike", {}).get("verdict") ==
          "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION")
    check("ReadAreaLike js linkage: callback_info_index=3, js_argument_index=4",
          findings_by_method.get("ReadAreaLike", {}).get("callback_info_index") == 3
          and findings_by_method.get("ReadAreaLike", {}).get("js_argument_index") == 4)
    check("ReadAreaLike carries the non-vulnerability-claim disclaimer",
          "STATIC CANDIDATE" in findings_by_method.get("ReadAreaLike", {}).get(
              "evidence_note", "") and
          "not a vulnerability" in findings_by_method.get("ReadAreaLike", {}).get(
              "evidence_note", "").lower())

    check("UploadLike -> NAN_NEWBUFFER_UNBOUNDED_ALLOCATION (positive, 2-arg overload)",
          findings_by_method.get("UploadLike", {}).get("verdict") ==
          "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION")

    check("GuardedLike -> UPPER_BOUND_CHECK_PRESENT (not promoted)",
          findings_by_method.get("GuardedLike", {}).get("verdict") ==
          "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_UPPER_BOUND_CHECK_PRESENT")
    check("GuardedLike bound evidence names the real size>65536 comparison, not the "
          "template-mislex artifact",
          findings_by_method.get("GuardedLike", {}).get("bound_check_evidence", {}).get(
              "code", "") == "size > 65536")

    check("InternalConstantLike -> SIZE_LITERAL_NOT_APPLICABLE (no finding record)",
          "InternalConstantLike" not in findings_by_method
          and cls.get("NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_SIZE_LITERAL_NOT_APPLICABLE") == 1)

    check("NotRegisteredLike -> NOT_JS_REGISTERED",
          findings_by_method.get("NotRegisteredLike", {}).get("verdict") ==
          "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_NOT_JS_REGISTERED")

    check("TopLevelLike -> JS_CALL_UNRESOLVED (registered, but no real JS call in fixture)",
          findings_by_method.get("TopLevelLike", {}).get("verdict") ==
          "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_JS_CALL_UNRESOLVED")

    check("exactly 2 real NAN_NEWBUFFER_UNBOUNDED_ALLOCATION positives",
          cls.get("NAN_NEWBUFFER_UNBOUNDED_ALLOCATION") == 2)

    # --- CopyBuffer contract -------------------------------------------------------------------
    check("CopyGoodLike -> CAPACITY_MATCHES_ALLOCATION (no finding record, not promoted)",
          "CopyGoodLike" not in findings_by_method
          and cls.get("NAN_COPYBUFFER_SOURCE_CAPACITY_CAPACITY_MATCHES_ALLOCATION") == 1)

    check("CopyMismatchLike -> NAN_COPYBUFFER_SOURCE_CAPACITY (positive)",
          findings_by_method.get("CopyMismatchLike", {}).get("verdict") ==
          "NAN_COPYBUFFER_SOURCE_CAPACITY")
    check("CopyMismatchLike records the real 128-vs-copyLen mismatch",
          findings_by_method.get("CopyMismatchLike", {}).get("alloc_size_arg_code") == "128"
          and findings_by_method.get("CopyMismatchLike", {}).get("copy_size_arg_code") ==
          "copyLen")
    check("CopyMismatchLike carries the OOB-read-shape disclaimer, not a CWE claim",
          "STATIC CANDIDATE" in findings_by_method.get("CopyMismatchLike", {}).get(
              "evidence_note", "")
          and "CWE" not in findings_by_method.get("CopyMismatchLike", {}).get(
              "evidence_note", "").replace("not a vulnerability or CWE claim", ""))

    check("CopyUnresolvedLike -> SOURCE_CAPACITY_UNRESOLVED (never inferred as OOB)",
          findings_by_method.get("CopyUnresolvedLike", {}).get("verdict") ==
          "NAN_COPYBUFFER_SOURCE_CAPACITY_UNRESOLVED")
    check("CopyUnresolvedLike's reason names the real opaque-field shape",
          "SOURCE_NOT_A_SIMPLE_LOCAL_IDENTIFIER" in
          findings_by_method.get("CopyUnresolvedLike", {}).get("reason", ""))

    check("exactly 1 real NAN_COPYBUFFER_SOURCE_CAPACITY positive",
          cls.get("NAN_COPYBUFFER_SOURCE_CAPACITY") == 1)

    # --- Never call a candidate a vulnerability/CWE in its own verdict string ------------------
    for f in doc["findings"]:
        check(f"verdict name for {f['method_name']} carries no CWE/vulnerability label",
              "CWE" not in f["verdict"] and "VULN" not in f["verdict"].upper())

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
