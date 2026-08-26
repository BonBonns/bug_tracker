#!/usr/bin/env python3
"""JS-PROV-R09 gate: registration recognition over ObservedParameterTypeFact.
Gate 1 closes only if /t3 (fake router) produces NO registration."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from framework_registration import derive  # noqa: E402

def main():
    d = derive(sys.argv[1])
    reg = {r["declaring_method"].split(":")[-1]: r for r in d["registrations"]}
    ab = {}
    for a in d["abstentions"]:
        ab.setdefault(a["receiver_param"].split(":")[-1].split("#")[0], set()).add(a["reason"])
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))

    ck("t2 REAL router: registration ESTABLISHED", "installReal" in reg, list(reg))
    ck("t2 framework identity is @koa/router",
       reg.get("installReal", {}).get("framework_identity") == "@koa/router")
    ck("t2 identity evidence is RECEIVER_DOMAIN_EVIDENCE (never methodFullName)",
       reg.get("installReal", {}).get("identity_evidence") == "RECEIVER_DOMAIN_EVIDENCE")
    ck("GATE-1: t3 FAKE router produces NO registration", "installFake" not in reg, list(reg))
    ck("t3 abstains as NOT_A_PROFILED_FRAMEWORK",
       "RECEIVER_NOT_A_PROFILED_FRAMEWORK" in ab.get("installFake", set()), ab.get("installFake"))
    ck("conflicting-receiver callsites produce NO registration", "installBoth" not in reg)
    ck("conflicting-receiver abstains as AMBIGUOUS_ACROSS_CALLSITES",
       "RECEIVER_AMBIGUOUS_ACROSS_CALLSITES" in ab.get("installBoth", set()), ab.get("installBoth"))
    ck("ANY-contaminated receiver produces NO registration", "installAny" not in reg)
    ck("ANY-contaminated abstains as DOMAIN_NOT_ESTABLISHED",
       "RECEIVER_DOMAIN_NOT_ESTABLISHED" in ab.get("installAny", set()), ab.get("installAny"))
    ck("exactly ONE registration in the fixture", len(d["registrations"]) == 1,
       [r["declaring_method"] for r in d["registrations"]])
    # The CPG's own receiver type is wrong here; recognition must not follow it.
    ck("recognition survives a WRONG cpg receiver type (disagreement recorded)",
       reg.get("installReal", {}).get("cpg_receiver_type_disagrees") is True,
       reg.get("installReal", {}).get("cpg_receiver_type"))

    # R26-FIXTURE-INTEGRITY: this gate keys assertions on declaring-method short name, which is
    # NOT globally unique in general -- it collides on real corpora. The gate is
    # correct only while its fixture keeps these keys distinct. Assert that, so
    # a future fixture addition fails LOUDLY instead of silently overwriting a
    # lookup entry and checking the wrong record (JS-PROV-R26).
    _keys = [r["declaring_method"].split(":")[-1] for r in d["registrations"]]
    _dupes = sorted({k for k in _keys if _keys.count(k) > 1})
    ck("R26-FIXTURE-INTEGRITY: assertion keys unique in this fixture", not _dupes, _dupes)

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R09={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
