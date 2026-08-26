#!/usr/bin/env python3
"""JS-PROV-R38 gate. Preregistered teeth; run against the R38 fixture raw dir.

Teeth (all must pass; each failure names what it caught):
  T1a/T1b  POSITIVE  app.use middleware before mount flows into BOTH mounted
                     routers' downstream readers, strength MAY (conditional write).
  T2       NEG-2     route-scoped writer on tags-router never joins the
                     articles reader of the same property (state.tag).
  T3       ORPHAN    the required-but-never-mounted router receives no flow.
  T4       ORDERING  app.use after the mount does not flow (state.late), and
                     the refusal is a RECORDED abstention, not silence.
  T5       R12 FROZEN  within-route flow (tagWriter->tagHandler state.tag MUST)
                     still present, and R12 emits no cross-registration flow.
  T6       STRENGTH  no cross-mount flow is MUST for a conditional write
                     (R19 two-axes rule across the mount).
  T7       MOUNT SET exactly the two mounted router files; orphan absent.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "portable-engine-full-review-package/frontends/javascript-typescript/joern-ts"))
from app_mount_flow import derive as derive_r38          # noqa: E402
from context_state_flow import derive as derive_r12      # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "r38-out" / "raw"
r38 = derive_r38(raw)
r12 = derive_r12(raw)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def flows_matching(flows, wtail, wpath, rtail, rpath):
    return [f for f in flows
            if f["writer_method"].endswith(wtail) and f["writer_path"] == wpath
            and f["reader_method"].endswith(rtail) and f["reader_path"] == rpath]


F = r38["flows"]

t1a = flows_matching(F, ":userMiddleware", "state.user", ":get", "state.user")
tooth("T1a user-mw -> articles ctrl.get (MAY)",
      len(t1a) == 1 and t1a[0]["state_flow_strength"] == "MAY"
      and t1a[0]["relation"] == "APP_MOUNT_UPSTREAM", str(t1a))

t1b = flows_matching(F, ":userMiddleware", "state.user", ":tagHandler", "state.user")
tooth("T1b user-mw -> tags handler (MAY)",
      len(t1b) == 1 and t1b[0]["state_flow_strength"] == "MAY", str(t1b))

t2 = [f for f in F if f["writer_method"].endswith(":tagWriter")]
tooth("T2 NEG-2: route-scoped tagWriter never crosses routers", len(t2) == 0, str(t2))

t3 = [f for f in F if "orphan" in f["reader_method"]]
tooth("T3 orphan router receives no middleware flow", len(t3) == 0, str(t3))

t4f = [f for f in F if f["writer_method"].endswith(":lateMiddleware")]
t4a = [a for a in r38["abstentions"]
       if a.get("reason") == "MIDDLEWARE_REGISTERED_AFTER_MOUNT"
       and "lateMiddleware" in str(a.get("middleware", ""))]
tooth("T4 late middleware: no flow AND recorded abstention",
      len(t4f) == 0 and len(t4a) >= 1, f"flows={t4f} abst={len(t4a)}")

r12_within = [f for f in r12["flows"]
              if f["writer_method"].endswith(":tagWriter")
              and f["reader_method"].endswith(":tagHandler")
              and f["writer_path"] == "state.tag"
              and f["state_flow_strength"] == "MUST"]
r12_cross = [f for f in r12["flows"]
             if f["writer_method"].split("::")[0] != f["reader_method"].split("::")[0]]
tooth("T5 R12 frozen: within-route MUST intact, no cross-registration flow",
      len(r12_within) == 1 and len(r12_cross) == 0,
      f"within={len(r12_within)} cross={len(r12_cross)}")

t6 = [f for f in F if f["state_flow_strength"] == "MUST"
      and f["writer_method"].endswith(":userMiddleware")]
tooth("T6 conditional write never MUST across the mount", len(t6) == 0, str(t6))

t8 = flows_matching(F, ":auditMiddleware", "state.audit",
                    ":exportedHandler", "state.audit")
tooth("T8 unconditional write IS MUST across the mount",
      len(t8) == 1 and t8[0]["state_flow_strength"] == "MUST", str(t8))

t9_bad = [f for f in F if f["reader_method"].endswith(":unexportedHandler")]
t9_good = flows_matching(F, ":userMiddleware", "state.user",
                         ":exportedHandler", "state.user")
multi = [m for m in r38["mounts"] if m["router_file"] == "routes/multi-router.js"]
tooth("T9 two-routers-one-file: only the EXPORTED router's regs join",
      len(t9_bad) == 0 and len(t9_good) == 1
      and len(multi) == 1 and multi[0]["router_local"] == "routerA"
      and len(multi[0]["mounted_registrations"]) == 1,
      f"bad={t9_bad} good={len(t9_good)} mounts={multi}")

mounted_files = sorted(m["router_file"] for m in r38["mounts"])
tooth("T7 mount set exact",
      mounted_files == ["routes/articles-router.js", "routes/multi-router.js", "routes/tags-router.js"],
      str(mounted_files))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"JS_PROV_R38={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
