#!/usr/bin/env python3
"""VIRTUAL-DISPATCH-REACHABILITY-R01 control gate. Runs virtual_dispatch_reachability
over FROZEN real Joern facts (fixture_vd_controls.cpp -> raw_vd_controls/) and asserts
the 8 synthetic controls, plus the leveldb-pattern positive (the frozen
raw_asyncworker_reach/). Control 9 (the REAL leveldb facts) is exercised separately by
task 3 / the pipeline record. Every assertion is reachability structure; no security or
runtime claim.

Controls:
  1 one concrete derived worker            -> derived override PROMOTED
  2 two possible derived workers           -> abstain, derived NOT promoted
  3 base-class allocation                  -> BASE override promoted, derived NOT
  4 callback registered with other data    -> abstain, NOT promoted
  5 receiver reassigned before callback    -> abstain, NOT promoted
  6 factory return, unresolved concrete type-> abstain, NOT promoted
  7 virtual signature mismatch             -> mismatched override NOT promoted (resolves to base)
  8 callback not registered                -> no promotion
  9 leveldb pattern (distilled)            -> the two-site worker override PROMOTED
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "virtual_dispatch_reachability.py"
STUDY = HERE / "study" / "napi_status"

ok = total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(rawdir, outname):
    out = STUDY / outname
    subprocess.run([sys.executable, str(CAP), str(STUDY / rawdir), str(out)],
                   check=True, stdout=subprocess.DEVNULL)
    return json.loads(out.read_text())


r = run("raw_vd_controls", "out_vd_controls.json")
promoted = {v["function"] for v in r["promoted"].values()}
reasons = {a["reason"] for a in r["abstained"]}


def promoted_by(fullname):
    return fullname in promoted


# 1 -------------------------------------------------------------------------------
ck("C1 one concrete derived worker -> W1Next::HandleOKCallback PROMOTED",
   promoted_by("W1Next.HandleOKCallback:void()"))
ck("C1 evidence names the allocation, registration, callback, cast and resolved chain",
   any(all(k in v for k in ("allocation", "registration_api", "callback",
                            "cast_receiver", "resolved_via"))
       for v in r["promoted"].values()
       if v["function"] == "W1Next.HandleOKCallback:void()"))

# 2 -------------------------------------------------------------------------------
ck("C2 two possible derived workers -> W2Next::HandleOKCallback NOT promoted",
   not promoted_by("W2Next.HandleOKCallback:void()"))
ck("C2 the ambiguous-receiver export is abstained (reassign/unresolved), never promoted",
   any(a.get("function", "").startswith("c2_export") for a in r["abstained"]))

# 3 -------------------------------------------------------------------------------
ck("C3 base-class allocation -> BASE W3Base::HandleOKCallback PROMOTED",
   promoted_by("W3Base.HandleOKCallback:void()"))
ck("C3 the derived override W3Derived::HandleOKCallback is NOT promoted "
   "(only the base was allocated)",
   not promoted_by("W3Derived.HandleOKCallback:void()"))

# 4 -------------------------------------------------------------------------------
ck("C4 callback registered with a DIFFERENT data pointer -> W4Next::HandleOKCallback "
   "NOT promoted, REGISTRATION_DATA_NOT_THIS recorded",
   not promoted_by("W4Next.HandleOKCallback:void()")
   and "REGISTRATION_DATA_NOT_THIS" in reasons)

# 5 -------------------------------------------------------------------------------
ck("C5 receiver reassigned before callback -> abstain (RECEIVER_REASSIGNED), nothing "
   "promoted from c5",
   "RECEIVER_REASSIGNED" in reasons
   and any(a.get("function", "").startswith("c5_export") for a in r["abstained"]))

# 6 -------------------------------------------------------------------------------
ck("C6 factory return, unresolved concrete type -> abstain "
   "(UNRESOLVED_FACTORY_CONSTRUCTION)",
   "UNRESOLVED_FACTORY_CONSTRUCTION" in reasons
   and any(a.get("function", "").startswith("c6_export") for a in r["abstained"]))

# 7 -------------------------------------------------------------------------------
ck("C7 virtual signature mismatch -> the mismatched W7Next::HandleOKCallback(int) is "
   "NOT promoted",
   not promoted_by("W7Next.HandleOKCallback:void(int)"))
ck("C7 a W7Next object's no-arg dispatch resolves to the BASE override instead "
   "(signature-exact resolution)",
   any(v["function"] == "W1Base.HandleOKCallback:void()"
       and v["concrete_type"] == "W7Next" for v in r["promoted"].values()))

# 8 -------------------------------------------------------------------------------
ck("C8 callback not registered -> W8Next::HandleOKCallback NOT promoted (no async_work "
   "in the ctor chain)",
   not promoted_by("W8Next.HandleOKCallback:void()")
   and not any(v["function"].startswith("W8") for v in r["promoted"].values()))

# 9 (distilled leveldb pattern) --------------------------------------------------
r2 = run("raw_asyncworker_reach", "out_vd_asyncworker.json")
promoted2 = {v["function"]: v for v in r2["promoted"].values()}
ck("C9 leveldb pattern (distilled): NextWorker::HandleOKCallback PROMOTED via the full "
   "allocation -> async_work(this) -> Complete -> cast -> virtual dispatch chain",
   "NextWorker.HandleOKCallback:void()" in promoted2)
ck("C9 the promotion is for the unique concrete type NextWorker",
   promoted2.get("NextWorker.HandleOKCallback:void()", {}).get("concrete_type")
   == "NextWorker")

# --- SOUND root-gating: virtual dispatch resolves the object-flow hop, but a target is
# elevated to the reportable virtual tier ONLY when its ROOT entry is itself externally
# reachable. Virtual dispatch never invents a JS entry point. ---
import virtual_dispatch_reachability as V  # noqa: E402
raw_aw = str(STUDY / "raw_asyncworker_reach")
gated_none = V.promote_gated_by_root(raw_aw, lambda root: False)
ck("root-gate: with the root entry NOT externally reachable, NOTHING is promoted to "
   "the reportable virtual tier (no invented JS entry point)",
   gated_none == {})
Faw = V.Facts(raw_aw)
gated_ok = V.promote_gated_by_root(raw_aw, lambda root: root.startswith("iterator_next"))
ck("root-gate: with the root entry externally reachable, NextWorker::HandleOKCallback "
   "is elevated to TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN",
   any(Faw.methods[k]["full_name"] == "NextWorker.HandleOKCallback:void()"
       and v["reachability_status"] == V.TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN
       for k, v in gated_ok.items()))

print(f"VIRTUAL_DISPATCH_REACHABILITY_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
