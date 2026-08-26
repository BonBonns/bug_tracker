#!/usr/bin/env python3
"""JS-PROV-R39 gate — measured on the REAL Corpus D (koa-knex-realworld-example).

Teeth:
  C1  the transcript's target flow exists: user-middleware's conditional
      `ctx.state.user` write reaches users-controller.get's read, MAY.
  C2  CEILING HOLDS: every cross-mount flow is MAY -- the write is conditional,
      and app-upstream ordering certainty never upgraded write strength.
  C3  ABSTAIN-NOT-FABRICATE: no flow reaches comments-controller. Its
      callbacks are 3-part members (`ctrl.comments.post`) -- an unresolved
      shape. Had a flow appeared there, THAT would be the bug.
  C4  the composition closure is exactly the six (file, local) router pairs:
      index.js{router,api} + the four leaf routers. Nothing extra reachable.
  C5  mounted registrations == 15 (get 7, post 6, put 2 -- the transcript's
      exact reader-side census).
  C6  R12 FROZEN on real code: zero cross-file flows from the within-route
      join; NEG-2 untouched.
  C7  refusals are RECORDED: external-package middleware (helmet(), jwt,
      routes.allowedMethods()) abstain with MIDDLEWARE_IDENTITY_UNKNOWN_OR_STUB
      rather than resolving to a guess.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "portable-engine-full-review-package/frontends/javascript-typescript/joern-ts"))
from app_mount_flow import derive as derive_r39          # noqa: E402
from context_state_flow import derive as derive_r12      # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "r39-out" / "raw"
r39 = derive_r39(raw)
r12 = derive_r12(raw)
F = r39["flows"]
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


c1 = [f for f in F if "user-middleware" in f["writer_method"]
      and f["writer_path"] == "state.user"
      and "users-controller" in f["reader_method"] and f["reader_method"].endswith(":get")
      and f["reader_path"] == "state.user"]
tooth("C1 target flow: user-mw state.user -> users-controller.get",
      len(c1) == 1 and c1[0]["state_flow_strength"] == "MAY", str(c1[:1]))

tooth("C2 ceiling: every cross-mount flow is MAY",
      len(F) > 0 and all(f["state_flow_strength"] == "MAY" for f in F),
      f"n={len(F)} strengths={sorted({f['state_flow_strength'] for f in F})}")

c3 = [f for f in F if "comments-controller" in f["reader_method"]]
tooth("C3 abstain-not-fabricate: no flow into comments-controller (3-part members)",
      len(c3) == 0, str(c3))

closures = [tuple(map(tuple, m["composition_closure"])) for m in r39["mounts"]]
expected = {("routes/articles-router.js", "router"), ("routes/index.js", "api"),
            ("routes/index.js", "router"), ("routes/profiles-router.js", "router"),
            ("routes/tags-router.js", "router"), ("routes/users-router.js", "router")}
tooth("C4 composition closure exact (6 pairs, nothing extra)",
      len(closures) == 1 and set(closures[0]) == expected, str(closures))

n_mounted = sum(len(m["mounted_registrations"]) for m in r39["mounts"])
tooth("C5 mounted registrations == 15 (transcript census)", n_mounted == 15, str(n_mounted))

r12_cross = [f for f in r12["flows"]
             if f["writer_method"].split("::")[0] != f["reader_method"].split("::")[0]]
tooth("C6 R12 frozen on real corpus: zero cross-file flows", len(r12_cross) == 0,
      str(r12_cross[:2]))

stub_abst = [a for a in r39["abstentions"]
             if a["reason"] == "MIDDLEWARE_IDENTITY_UNKNOWN_OR_STUB"]
codes = " ".join(str(a.get("code", "")) for a in stub_abst)
tooth("C7 external middleware refusals recorded (helmet/jwt/allowedMethods)",
      "helmet()" in codes and "jwt" in codes and "allowedMethods" in codes,
      codes[:120])

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"JS_PROV_R39={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
