#!/usr/bin/env python3
"""JS-PROV-R08 gate: ObservedParameterTypeFact acceptance.

Decisive control from JS-PROV-R07, with the wording adopted from R07's review:
  /t2 real router through a helper -> receives SUFFICIENT receiver-domain
      evidence to establish @koa/router under the R04/R05 evidence rules
  /t3 fake router through a helper -> must NOT gain @koa/router
"""
import json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from observed_parameter_types import derive  # noqa: E402

def main():
    d = derive(sys.argv[1])
    by = {f["callee_full_name"].split(":")[-1]: f for f in d["facts"]}
    ab = {}
    for a in d["abstentions"]:
        ab.setdefault(a["callee_full_name"].split(":")[-1], set()).add(a["reason"])
    checks = []
    def ck(n, ok, detail=""):
        checks.append((n, bool(ok), detail))

    r = by.get("installReal")
    ck("t2 REAL router: establishes @koa/router",
       r and r["observed_types"] == ["@koa/router"] and r["domain_established"], r)
    f = by.get("installFake")
    ck("t3 FAKE router: does NOT gain @koa/router",
       f and "@koa/router" not in f["observed_types"], f)
    ck("t3 FAKE router: observes its own concrete type instead",
       f and any("FakeRouter" in t for t in f["observed_types"]), f)
    b = by.get("installBoth")
    ck("conflicting callsites -> SET of both (never last-wins)",
       b and len(b["observed_types"]) == 2
         and "@koa/router" in b["observed_types"]
         and any("FakeRouter" in t for t in b["observed_types"]), b)
    a = by.get("installAny")
    ck("ANY callsite -> unconstrained_callsite TRUE", a and a["unconstrained_callsite"], a)
    ck("ANY callsite -> domain NOT established despite a concrete observation",
       a and not a["domain_established"], a)
    ck("cast-erased argument abstains (G2/G3)", "installCast" in ab, ab.get("installCast"))
    ck("stronger declared param type abstains (G4)",
       "G4_DECLARED_TYPE_PRESENT" in ab.get("installDeclared", set()), ab.get("installDeclared"))
    ck("rest parameter abstains", "installRest" in ab, ab.get("installRest"))
    ck("every fact carries declared_type alongside (never replaced)",
       all("declared_type" in x for x in d["facts"]))
    ck("every fact resolution is CALLSITE_PROPAGATED",
       all(x["resolution"] == "CALLSITE_PROPAGATED" for x in d["facts"]))
    ck("no operator intrinsic became a propagation target (G7)",
       not any(x["callee_full_name"].startswith("<operator>.") for x in d["facts"]))

    # R26-FIXTURE-INTEGRITY: this gate keys assertions on the callee SHORT NAME,
    # which is not globally unique -- it collides on real corpora. The gate is
    # correct only while its fixture keeps these keys distinct. Assert it, so a
    # future fixture addition fails LOUDLY instead of silently overwriting a
    # lookup entry and checking the wrong record (JS-PROV-R26).
    _keys = [f["callee_full_name"].split(":")[-1] for f in d["facts"]]
    _dupes = sorted({k for k in _keys if _keys.count(k) > 1})
    ck("R26-FIXTURE-INTEGRITY: assertion keys unique in this fixture", not _dupes, _dupes)

    for n, ok, det in checks:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in checks if ok)
    print(f"JS_PROV_R08={p}/{len(checks)}")
    sys.exit(0 if p == len(checks) else 1)

if __name__ == "__main__":
    main()
