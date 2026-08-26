#!/usr/bin/env python3
"""Guard-fallthrough detector gate. Preregistered teeth on the guard fixture.

The fixture encodes the Pods pods_error() bypass class plus discriminating
negative controls, so passing requires the detector to separate the vulnerable
shape from look-alikes -- not merely to fire.

  G1 DETECT      adminAjax's two bare guard calls -> CANDIDATE_GUARD_FALLTHROUGH.
  G2 TERMINATOR  denyRequest classified CONDITIONAL (throws on one path, returns
                 a value on another); denyAlways classified ALWAYS.
  G3 RETURN-SAFE safeReturn (same CONDITIONAL callee, but `return deny...`) ->
                 SAFE_RETURNED, never a candidate.
  G4 ALWAYS-SAFE safeAlways (bare call, but ALWAYS-terminating callee) ->
                 SAFE_ALWAYS_TERMINATES, never a candidate. This is the tooth
                 that stops the detector from flagging every bare guard call.
  G5 NO FALSE +  exactly two CANDIDATE findings in the whole fixture.
  G6 CALLEE ID   the candidate's callee resolves to lib/guard-lib.js's
                 denyRequest via the import, NOT the frontend's same-file guess
                 (the JS-PROV-R13 lesson: code-string callees are not identity).
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from guard_fallthrough_verdict import derive  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "guard-out" / "raw"
d = derive(raw)
F = d["findings"]
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def find(method_suffix, line):
    for f in F:
        if f["method"].endswith(method_suffix) and f["line"] == line:
            return f
    return None


cands = [f for f in F if f["verdict"] == "CANDIDATE_GUARD_FALLTHROUGH"]
admin = [f for f in cands if "adminAjax" in f["method"]]
tooth("G1 adminAjax bare guards flagged (2 candidates)", len(admin) == 2, str([f["line"] for f in admin]))

# terminator classifications, read straight from the fact file
term = {r[1]: r[2] for r in (ln.split("\t") for ln in
        (Path(raw) / "terminator_profile.tsv").read_text().splitlines()) if len(r) == 4}
tooth("G2 denyRequest=CONDITIONAL, denyAlways=ALWAYS",
      term.get("lib/guard-lib.js::program:denyRequest") == "CONDITIONAL"
      and term.get("lib/guard-lib.js::program:denyAlways") == "ALWAYS",
      f"deny={term.get('lib/guard-lib.js::program:denyRequest')} always={term.get('lib/guard-lib.js::program:denyAlways')}")

sr = find(":safeReturn", 7)
tooth("G3 safeReturn -> SAFE_RETURNED", sr is not None and sr["verdict"] == "SAFE_RETURNED",
      str(sr and sr["verdict"]))

sa = find(":safeAlways", 6)
tooth("G4 safeAlways -> SAFE_ALWAYS_TERMINATES (bare call, always-terminating callee)",
      sa is not None and sa["verdict"] == "SAFE_ALWAYS_TERMINATES", str(sa and sa["verdict"]))

tooth("G5 exactly two candidates in the fixture (no false positives)", len(cands) == 2, str(len(cands)))

tooth("G6 candidate callee resolved to lib/guard-lib denyRequest via import (not same-file guess)",
      all(f.get("callee_resolved") == "lib/guard-lib.js::program:denyRequest"
          and f.get("callee_resolution") == "DESTRUCTURED_IMPORT" for f in admin),
      str([(f.get("callee_resolved"), f.get("callee_resolution")) for f in admin]))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"GUARD_FALLTHROUGH={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
