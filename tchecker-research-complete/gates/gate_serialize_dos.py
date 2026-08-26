#!/usr/bin/env python3
"""Unguarded-serialize DoS detector gate (CWE-674).

Fixture reproduces the Unleash JSON.stringify crash plus four controls, each
isolating one leg (try/catch, depth guard, non-attacker data, uncaughtException
net). Passing requires the four-leg co-occurrence logic, not firing on any
serialize call.

  S1 DETECT      ser-vuln -> CANDIDATE_UNGUARDED_SERIALIZE_DOS.
  S2 LEGS        ser-vuln: attacker-controlled, not in try/catch, no depth guard,
                 no uncaughtException handler.
  S3 TRYCATCH    ser-trycatch -> SAFE_TRY_CATCH.
  S4 DEPTHGUARD  ser-guarded -> SAFE_DEPTH_GUARDED.
  S5 NONATTACK   ser-nonattacker -> SAFE_NOT_ATTACKER_CONTROLLED.
  S6 NET         ser-hashandler (uncaughtException present) ->
                 SUSPICIOUS_UNGUARDED_SERIALIZE (de-escalated, not a hard crash).
  S7 NO FALSE +  exactly one CANDIDATE across the fixture.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from serialize_dos_verdict import derive  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "ser-out" / "raw"
F = derive(raw)["findings"]
by = {f["package"]: f for f in F}
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


v = by.get("ser-vuln")
tooth("S1 ser-vuln -> CANDIDATE_UNGUARDED_SERIALIZE_DOS",
      v is not None and v["verdict"] == "CANDIDATE_UNGUARDED_SERIALIZE_DOS", str(v and v["verdict"]))

tooth("S2 ser-vuln legs: attacker + no try + no depth guard + no net",
      v is not None and v["attacker_controlled"] and not v["in_try_catch"]
      and not v["depth_guarded"] and not v["uncaught_handler_present"],
      str(v and (v["attacker_controlled"], v["in_try_catch"], v["depth_guarded"], v["uncaught_handler_present"])))

tc = by.get("ser-trycatch")
tooth("S3 ser-trycatch -> SAFE_TRY_CATCH",
      tc is not None and tc["verdict"] == "SAFE_TRY_CATCH", str(tc and tc["verdict"]))

g = by.get("ser-guarded")
tooth("S4 ser-guarded -> SAFE_DEPTH_GUARDED",
      g is not None and g["verdict"] == "SAFE_DEPTH_GUARDED", str(g and g["verdict"]))

na = by.get("ser-nonattacker")
tooth("S5 ser-nonattacker -> SAFE_NOT_ATTACKER_CONTROLLED",
      na is not None and na["verdict"] == "SAFE_NOT_ATTACKER_CONTROLLED", str(na and na["verdict"]))

hh = by.get("ser-hashandler")
tooth("S6 ser-hashandler -> SUSPICIOUS_UNGUARDED_SERIALIZE (net present)",
      hh is not None and hh["verdict"] == "SUSPICIOUS_UNGUARDED_SERIALIZE", str(hh and hh["verdict"]))

cands = [f for f in F if f["verdict"] == "CANDIDATE_UNGUARDED_SERIALIZE_DOS"]
tooth("S7 exactly two candidates (Express ser-vuln + Hapi ser-hapi)", len(cands) == 2,
      str(sorted(f["package"] for f in cands)))

hapi = by.get("ser-hapi")
tooth("S8 Hapi request.payload recognized as attacker source -> CANDIDATE",
      hapi is not None and hapi["verdict"] == "CANDIDATE_UNGUARDED_SERIALIZE_DOS"
      and hapi["attacker_controlled"], str(hapi and hapi["verdict"]))

lit = by.get("ser-literal")
tooth("S9 bounded literal of scalars (taint reaches) -> SAFE_BOUNDED_LITERAL",
      lit is not None and lit["verdict"] == "SAFE_BOUNDED_LITERAL"
      and lit["attacker_controlled"] and lit["bounded_literal"],
      str(lit and lit["verdict"]))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"SERIALIZE_DOS={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
