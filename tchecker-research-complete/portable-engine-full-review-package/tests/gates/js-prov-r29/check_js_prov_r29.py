#!/usr/bin/env python3
"""JS-PROV-R29 gate: direct (non-parameter) receiver framework registration.
Isolated fixture -- JS-PROV-R26/R29 lesson: merging fixture files into one CPG
lets short-name collisions (two `FakeRouter` classes) perturb type recovery and
break unrelated assertions."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from framework_registration import derive  # noqa: E402

def main():
    d = derive(sys.argv[1])
    direct = [r for r in d["registrations"] if r["identity_evidence"] == "DIRECT_RECEIVER_TYPE"]
    dl = {r.get("receiver_local") for r in direct}
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))
    ck("R29 profiled direct receiver establishes a registration", "real" in dl, sorted(dl))
    ck("R29 DECISIVE NEGATIVE: non-profiled concrete type (FakeRouter) yields nothing",
       "fr" not in dl, sorted(dl))
    ck("R29 object-literal receiver yields nothing", "objLit" not in dl, sorted(dl))
    ck("R29 ANY / globalThis receiver yields nothing", "opaque" not in dl, sorted(dl))
    ck("R29 exactly one registration in this fixture", len(d["registrations"]) == 1,
       [(r.get("receiver_local"), r["verb"]) for r in d["registrations"]])
    ck("R29 evidence labelled DIRECT_RECEIVER_TYPE, distinct from the parameter path",
       all(r["identity_evidence"] == "DIRECT_RECEIVER_TYPE" for r in direct))
    ck("R29 framework identity comes from the closed profile, not a name",
       all(r["framework_identity"] in ("@koa/router", "koa-router", "koa", "express")
           for r in direct), [r["framework_identity"] for r in direct])
    ck("R29 methodFullName / resolved callee never used as evidence (JS-PROV-R07)",
       all(r["identity_evidence"] in ("DIRECT_RECEIVER_TYPE", "RECEIVER_DOMAIN_EVIDENCE")
           for r in d["registrations"]))
    _k = [r["registration_call_id"] for r in d["registrations"]]
    ck("R26-FIXTURE-INTEGRITY: assertion keys unique", len(_k) == len(set(_k)))
    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R29={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
