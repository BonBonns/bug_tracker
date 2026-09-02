#!/usr/bin/env python3
"""SERIALIZE-DOS-R01 control gate.

Fixtures (fixtures/src/*, real-Joern-compiled via jssrc2cpg + the two producers in
producers/, see fixtures/raw/) cover, per RECONCILIATION.md's decision to preserve two
independent axes:

  POSITIVE (both axes candidate)         sd-crash-vuln, sd-hapi
  GUARDED-NEGATIVE (crash axis SAFE;
    size axis still a candidate --
    the documented two-axis disagreement) sd-crash-trycatch, sd-crash-depthguard
  ORDINARY-NEGATIVE (both axes safe,
    not attacker-controlled at all)       sd-nonattacker
  ABSTENTION (size axis abstains on a
    detected transform; crash axis is
    still a candidate -- no guard there)  sd-transform-present
  SUSPICIOUS (crash axis de-escalated
    by a package-level uncaughtException
    net; size axis still a candidate)     sd-hashandler

  D1  sd-crash-vuln         -> crash CANDIDATE_UNGUARDED_SERIALIZE_DOS,
                                 size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE
  D2  sd-hapi                -> same as D1 (Hapi request.payload source)
  D3  sd-crash-trycatch      -> crash SAFE_TRY_CATCH,
                                 size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE  (axes disagree)
  D4  sd-crash-depthguard    -> crash SAFE_DEPTH_GUARDED,
                                 size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE  (axes disagree)
  D5  sd-nonattacker         -> crash SAFE_NOT_ATTACKER_CONTROLLED,
                                 size  SAFE_NOT_ATTACKER_CONTROLLED        (axes agree)
  D6  sd-transform-present   -> crash CANDIDATE_UNGUARDED_SERIALIZE_DOS,
                                 size  ABSTAIN_TRANSFORM_PRESENT           (axes disagree)
  D7  sd-hashandler          -> crash SUSPICIOUS_UNGUARDED_SERIALIZE,
                                 size  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE  (axes disagree)
  D8  every finding carries reportable=false (pipeline integration deferred)
  D9  transform_callee is recorded (not just the boolean) on the one real transform site
  D10 no exploitability/vulnerability/severity language anywhere in the derive() output
      (claims-boundary lint, same discipline as the rest of this session's properties)
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from serialize_dos_r01 import derive  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "raw"
result = derive(raw)
F = result["findings"]
by = {f["package"]: f for f in F}
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def check(name, pkg, crash, size):
    f = by.get(pkg)
    ok = (f is not None and f["crash_dos_classification"] == crash
          and f["size_structure_dos_classification"] == size)
    detail = str(f and (f["crash_dos_classification"], f["size_structure_dos_classification"]))
    tooth(name, ok, detail)


check("D1 sd-crash-vuln", "sd-crash-vuln",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE")
check("D2 sd-hapi", "sd-hapi",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE")
check("D3 sd-crash-trycatch (axes disagree)", "sd-crash-trycatch",
      "SAFE_TRY_CATCH", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE")
check("D4 sd-crash-depthguard (axes disagree)", "sd-crash-depthguard",
      "SAFE_DEPTH_GUARDED", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE")
check("D5 sd-nonattacker (axes agree, both safe)", "sd-nonattacker",
      "SAFE_NOT_ATTACKER_CONTROLLED", "SAFE_NOT_ATTACKER_CONTROLLED")
check("D6 sd-transform-present (size abstains)", "sd-transform-present",
      "CANDIDATE_UNGUARDED_SERIALIZE_DOS", "ABSTAIN_TRANSFORM_PRESENT")
check("D7 sd-hashandler (crash de-escalated)", "sd-hashandler",
      "SUSPICIOUS_UNGUARDED_SERIALIZE", "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE")

tooth("D8 every finding carries reportable=false",
      len(F) > 0 and all(f["reportable"] is False for f in F),
      str([f["reportable"] for f in F]))

tp = by.get("sd-transform-present")
tooth("D9 transform_callee recorded on the real transform site",
      tp is not None and tp["transform_present"] is True and tp["transform_callee"] == "sanitizePayload",
      str(tp and (tp["transform_present"], tp["transform_callee"])))

blob = json.dumps(result).lower()
# Same convention as the rest of this session's properties (e.g.
# check_napi_status_leveldb_regression.py): only "vulnerab" is banned. The disclaimer
# text is EXPECTED to say "no exploitability claim is made" / "no severity claim is
# made" -- those words in a negation are the claims boundary working as intended, not
# a violation of it.
tooth("D10 no vulnerability language in the output (claims-boundary lint)",
      "vulnerab" not in blob, "")

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"SERIALIZE_DOS_R01={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
