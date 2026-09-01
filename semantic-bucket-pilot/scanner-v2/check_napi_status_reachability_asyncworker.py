#!/usr/bin/env python3
"""NAPI-STATUS reachability regression: proves, over FROZEN real Joern facts, WHY
@8crafter/leveldb-zlib's NextWorker::HandleOKCallback (the two STATUS_GUARD_MISSING
sites) is classified TIER_INTERNAL_UNREGISTERED -- and that this is the correct,
conservative outcome, not a gap in recognizing the async-work registration.

The structural break (traced in HANDLEOK_REACHABILITY_TRACE.json against the real
package, reproduced here on the distilled fixture_asyncworker_reach.cpp / frozen facts
cpp_facts_asyncworker_reach.json):

  napi_create_async_work registers the STATIC trampolines Execute/Complete (METHOD_REFs)
  -> Complete -> DoComplete -> HandleOKCallback is a VIRTUAL call the frontend binds to
  the BASE (BaseWorker::HandleOKCallback) -> the DERIVED override
  (NextWorker::HandleOKCallback) has NO incoming call edge.

So the async-work registration IS recognized (Execute/Complete promote to
TIER_CALLBACK_OR_WORKER_PROVEN), but that recognition does NOT propagate across the
second-order handoff + ambiguous virtual dispatch to the derived override -- exactly
the abstention the user specified ("second-order callback handoffs" and "ambiguous
virtual dispatch" stay internal/unresolved). The facts cannot prove a unique JS-to-
native chain to the site; it correctly stays non-reportable. No security or runtime
claim is made.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import reachability_tier as R  # noqa: E402

STUDY = HERE / "study" / "napi_status"
CPP = json.loads((STUDY / "cpp_facts_asyncworker_reach.json").read_text())
RAW = STUDY / "raw_asyncworker_reach"

ok = total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


fn_by_full = {f["full_name"]: f for f in CPP["functions"]}


def classify(full_name, js):
    fid = fn_by_full[full_name]["id"]
    table = R.build_registration_table(CPP)
    linked, _ = R.link_js_calls(js, CPP, table)
    clean = R.build_clean_call_edges(CPP)
    fn_names = {f["id"]: f.get("full_name") for f in CPP["functions"]}
    mrt = R.resolve_method_ref_targets(CPP)
    init_ids = {f["id"] for f in CPP["functions"] if f["name"] == "Init"}
    return R.classify_function_reachability(fid, table, linked, True, clean, fn_names,
                                            mrt, init_ids)["reachability_status"]


# schema-valid minimal JS facts so facts_available is True (native-tier classification
# does not depend on real JS links here -- we assert the native tiers)
JS = {"calls": [{"id": 1, "name": "iteratorNext", "full_name": "iteratorNext",
                 "callee_name": "iteratorNext", "arguments": []}],
      "functions": [{"id": 1, "name": "main", "full_name": "main"}]}

# --- the scanner still sees the two guard-missing sites at this INTERNAL function ---
out = STUDY / "out_asyncworker_reach.json"
subprocess.run([sys.executable, str(HERE / "napi_status_verdict_r02.py"), str(RAW),
                str(out)], check=True, stdout=subprocess.DEVNULL)
scan = json.loads(out.read_text())
gm = [f for f in scan["findings"] if f["verdict"] == "STATUS_GUARD_MISSING"]
ck("scanner finds the two STATUS_GUARD_MISSING/STATUS_DISCARDED sites in "
   "NextWorker::HandleOKCallback (the reachability question is about a REAL finding site)",
   len(gm) == 2 and all(f["method_name"] == "HandleOKCallback"
                        and f["sub_reason"] == "STATUS_DISCARDED" for f in gm))

# --- the registration IS recognized: the async-work trampolines promote ---
ck("napi_create_async_work's registered trampoline Execute -> TIER_CALLBACK_OR_WORKER_PROVEN "
   "(the registration API is recognized)",
   classify("BaseWorker.Execute:void(napi_env,void*)", JS)
   == R.TIER_CALLBACK_OR_WORKER_PROVEN)
ck("napi_create_async_work's registered trampoline Complete -> TIER_CALLBACK_OR_WORKER_PROVEN",
   classify("BaseWorker.Complete:void(napi_env,napi_status,void*)", JS)
   == R.TIER_CALLBACK_OR_WORKER_PROVEN)

# --- but it does NOT propagate past the second-order/virtual-dispatch hop ---
ck("the DERIVED override NextWorker::HandleOKCallback (the finding site) stays "
   "TIER_INTERNAL_UNREGISTERED -- the break is the second-order handoff + virtual dispatch",
   classify("NextWorker.HandleOKCallback:void()", JS) == R.TIER_INTERNAL_UNREGISTERED)
ck("even the BASE BaseWorker::HandleOKCallback stays TIER_INTERNAL_UNREGISTERED "
   "(reached only through the Complete trampoline, not a registered root)",
   classify("BaseWorker.HandleOKCallback:void()", JS) == R.TIER_INTERNAL_UNREGISTERED)

# --- the structural facts behind that verdict ---
ck("ZERO METHOD_REF/address-of references to any HandleOKCallback (it is never passed "
   "as a callback -- only Execute/Complete are)",
   not any(("addressOf" in c["name"] or "methodRef" in c["name"].lower())
           and any(fn_by_full.get(fn, {}).get("id") in c.get("candidate_target_ids", [])
                   for fn in ("BaseWorker.HandleOKCallback:void()",
                              "NextWorker.HandleOKCallback:void()"))
           for c in CPP["calls"]))
docomplete_hok = [c for c in CPP["calls"]
                  if c["name"] == "HandleOKCallback"
                  and fn_by_full["BaseWorker.DoComplete:void()"]["id"] == c["enclosing_function_id"]]
ck("the virtual call DoComplete -> HandleOKCallback binds to the BASE only "
   "(single candidate = BaseWorker::HandleOKCallback), not the derived override",
   len(docomplete_hok) == 1
   and docomplete_hok[0].get("candidate_target_full_names") == ["BaseWorker.HandleOKCallback:void()"])
nw_id = fn_by_full["NextWorker.HandleOKCallback:void()"]["id"]
ck("NextWorker::HandleOKCallback has NO incoming call edge at all (the polymorphic hop "
   "to the derived override is invisible to the frontend's call resolution)",
   not any(nw_id in c.get("candidate_target_ids", []) for c in CPP["calls"]))

# --- and therefore it is not in the reportable-reachability allowlist ---
import staged_enablement as se  # noqa: E402
ck("TIER_INTERNAL_UNREGISTERED is NOT an externally-reachable (reportable) tier -- the "
   "finding stays non-reportable, correctly and conservatively",
   R.TIER_INTERNAL_UNREGISTERED not in se._EXTERNALLY_REACHABLE_TIERS)

print(f"NAPI_STATUS_REACHABILITY_ASYNCWORKER={ok}/{total}")
sys.exit(0 if ok == total else 1)
