#!/usr/bin/env python3
"""Global shared-singleton security-control mutation detector gate (CWE-116).

Fixture reproduces the Unleash Mustache.escape override plus three negative
controls, each isolating one way the pattern is not present. Passing requires
the import-vs-local and write-vs-percall discriminators to hold.

  G1 DETECT     gmut-vuln (Mustache.escape = identity, imported) ->
                CANDIDATE_GLOBAL_SECURITY_OVERRIDE, confidence HIGH.
  G2 IMPORT     the candidate's base is an imported module and the rhs is an
                identity function.
  G3 PERCALL    gmut-percall (override in per-call options obj) ->
                SAFE_PERCALL_OVERRIDE.
  G4 LOCAL      gmut-local (mutates a local object, not imported) ->
                SAFE_LOCAL_OBJECT_MUTATION. The tooth that stops flagging every
                `.escape =` assignment.
  G5 READONLY   gmut-readonly (reads escape, never assigns) ->
                SAFE_NO_SINGLETON_WRITE.
  G6 NO FALSE + exactly one CANDIDATE across the fixture.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from globalmut_verdict import derive  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "gmut-out" / "raw"
F = derive(raw)["findings"]
by = {f["package"]: f for f in F}
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


v = by.get("gmut-vuln")
tooth("G1 gmut-vuln -> CANDIDATE_GLOBAL_SECURITY_OVERRIDE (HIGH)",
      v is not None and v["verdict"] == "CANDIDATE_GLOBAL_SECURITY_OVERRIDE"
      and v.get("confidence") == "HIGH", str(v and v["verdict"]))

tooth("G2 candidate base imported + rhs identity function",
      v is not None and v.get("base") == "Mustache" and v.get("member") == "escape"
      and v.get("identity_function") is True,
      str(v and (v.get("base"), v.get("identity_function"))))

p = by.get("gmut-percall")
tooth("G3 gmut-percall -> SAFE_PERCALL_OVERRIDE",
      p is not None and p["verdict"] == "SAFE_PERCALL_OVERRIDE", str(p and p["verdict"]))

lo = by.get("gmut-local")
tooth("G4 gmut-local -> SAFE_LOCAL_OBJECT_MUTATION",
      lo is not None and lo["verdict"] == "SAFE_LOCAL_OBJECT_MUTATION", str(lo and lo["verdict"]))

ro = by.get("gmut-readonly")
tooth("G5 gmut-readonly -> SAFE_NO_SINGLETON_WRITE",
      ro is not None and ro["verdict"] == "SAFE_NO_SINGLETON_WRITE", str(ro and ro["verdict"]))

cands = [f for f in F if f["verdict"] == "CANDIDATE_GLOBAL_SECURITY_OVERRIDE"]
tooth("G6 exactly one candidate", len(cands) == 1, str(len(cands)))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"GLOBALMUT={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
