#!/usr/bin/env python3
"""Validation-bypass (loop-control divergence) detector gate.

The fixture encodes the Elementor Pro Upload::validation() early-return bug
plus the discriminating negative controls that live in the original code
itself (error-recording returns are safe; continue is safe). Passing requires
separating the silent per-element return from its safe look-alikes, not merely
firing on any early return.

  V1 DETECT      validation:15 (silent per-element return, no error recorded) ->
                 CANDIDATE_VALIDATION_BYPASS.
  V2 PAIRING     the candidate is paired with processField's continue-loop over
                 the SAME collection (files[id] ~ files[id].entries()).
  V3 ERROR-SAFE  validation:20 and :24 (return AFTER addError) -> SAFE_RECORDS_
                 ERROR. This is the tooth that stops flagging every loop return.
  V4 CONTINUE    validationSafe:7 and processField:8 (continue) -> SAFE_CONTINUE.
  V5 WHOLE-COLL  the maxFiles return (line 9, outside the per-element loop) is
                 never a candidate (it's a whole-collection guard).
  V6 NO FALSE +  exactly one CANDIDATE_VALIDATION_BYPASS in the whole fixture.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from validation_bypass_verdict import derive  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "loop-out" / "raw"
F = derive(raw)["findings"]
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def find(meth_suffix, exit_line):
    for f in F:
        if f["method"].endswith(meth_suffix) and f["exit_line"] == str(exit_line):
            return f
    return None


cand = [f for f in F if f["verdict"] == "CANDIDATE_VALIDATION_BYPASS"]
v = find(":validation", 15)
tooth("V1 validation:15 silent return -> CANDIDATE_VALIDATION_BYPASS",
      v is not None and v["verdict"] == "CANDIDATE_VALIDATION_BYPASS", str(v and v["verdict"]))

tooth("V2 candidate paired with processField over same collection",
      v is not None and any("processField" in p["method"]
                            for p in v.get("paired_processing_loops", []))
      and v.get("collection") == "files[id]",
      str(v and (v.get("collection"), [p["method"] for p in v.get("paired_processing_loops", [])])))

s20, s24 = find(":validation", 20), find(":validation", 24)
tooth("V3 error-recording returns (20,24) -> SAFE_RECORDS_ERROR",
      s20 is not None and s20["verdict"] == "SAFE_RECORDS_ERROR"
      and s24 is not None and s24["verdict"] == "SAFE_RECORDS_ERROR",
      str((s20 and s20["verdict"], s24 and s24["verdict"])))

cs, cp = find(":validationSafe", 7), find(":processField", 8)
tooth("V4 continue exits -> SAFE_CONTINUE",
      cs is not None and cs["verdict"] == "SAFE_CONTINUE"
      and cp is not None and cp["verdict"] == "SAFE_CONTINUE",
      str((cs and cs["verdict"], cp and cp["verdict"])))

# the maxFiles whole-collection return (line 9) must not be a per-element candidate;
# it is outside the loop so it should not appear as a RETURN loop-exit at all.
whole = [f for f in F if f["exit_line"] == "9"]
tooth("V5 maxFiles whole-collection return never flagged",
      all(f["verdict"] != "CANDIDATE_VALIDATION_BYPASS" for f in whole), str(whole))

tooth("V6 exactly one CANDIDATE_VALIDATION_BYPASS in fixture", len(cand) == 1, str(len(cand)))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"VALIDATION_BYPASS={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
