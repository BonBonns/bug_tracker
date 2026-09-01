#!/usr/bin/env python3
"""Structural reachability trace for NextWorker::HandleOKCallback in the REAL leveldb
cpp facts. Proves each hop the user asked for, from the facts alone (not source)."""
import json

import os
d = json.load(open(os.environ.get("LEVELDB_CPP_FACTS", os.path.expanduser("~/leveldb_facts/cpp_facts_full.json"))))
fns = {f["id"]: f for f in d["functions"]}
calls = d["calls"]
by_name = {}
for f in d["functions"]:
    by_name.setdefault(f["name"], []).append(f)

print("=== 1. All HandleOKCallback definitions (virtual overrides) ===")
hok = by_name.get("HandleOKCallback", [])
for f in hok:
    print(f"  id={f['id']} full_name={f['full_name']} line={f['line']} external={f['is_external']}")
hok_ids = {f["id"] for f in hok}

print("\n=== 2. Any METHOD_REF / address-of to HandleOKCallback directly? ===")
# A call whose candidate targets or code references HandleOKCallback as a bare ref.
direct_refs = [c for c in calls if any(t in hok_ids for t in c.get("candidate_target_ids", []))
               and ("addressOf" in c["name"] or "methodRef" in c["name"].lower())]
print(f"  address-of/method-ref nodes targeting HandleOKCallback: {len(direct_refs)}")

print("\n=== 3. napi_create_async_work call(s) and the callback args registered ===")
naw = [c for c in calls if c["name"] == "napi_create_async_work"]
for c in naw:
    print(f"  call id={c['id']} in fn={fns.get(c['enclosing_function_id'],{}).get('full_name')} line={c['line']}")
    for a in c.get("arguments", []):
        code = a.get("code", "")
        if "Execute" in code or "Complete" in code:
            print(f"     callback arg: code={code!r} kind={a.get('kind') or a.get('label')}")

print("\n=== 4. The virtual dispatch hop: calls to HandleOKCallback (by name) and their candidate counts ===")
hok_calls = [c for c in calls if c["name"] == "HandleOKCallback"]
for c in hok_calls:
    tids = c.get("candidate_target_ids", [])
    print(f"  call id={c['id']} in fn={fns.get(c['enclosing_function_id'],{}).get('name')} "
          f"line={c['line']} dispatch={c.get('dispatch_type')} "
          f"candidates={len(tids)} -> {[fns.get(t,{}).get('full_name') for t in tids]}")

print("\n=== 5. Chain root: does a registered JS export construct NextWorker and Queue it? ===")
# iterator_next -> NextWorker ctor + Queue
itnext = [f for f in d["functions"] if f["name"] == "iterator_next"]
print(f"  iterator_next defs: {[(f['id'], f['full_name']) for f in itnext]}")
for f in itnext:
    body_calls = [c for c in calls if c["enclosing_function_id"] == f["id"]]
    interesting = [c for c in body_calls if c["name"] in
                   ("NextWorker", "Queue") or "NextWorker" in (c.get("method_full_name") or "")
                   or "Queue" in c["name"]]
    for c in interesting:
        print(f"     calls {c['name']!r} (mfn={c.get('method_full_name')}) line={c['line']} "
              f"candidates={len(c.get('candidate_target_ids', []))}")

print("\n=== 6. Complete trampoline -> DoComplete -> HandleOKCallback edge resolution ===")
comp = [f for f in d["functions"] if f["name"] == "Complete"]
for f in comp:
    bc = [c for c in calls if c["enclosing_function_id"] == f["id"]]
    print(f"  Complete id={f['id']} calls: {[(c['name'], len(c.get('candidate_target_ids',[]))) for c in bc]}")
docomp = [f for f in d["functions"] if f["name"] == "DoComplete"]
for f in docomp:
    bc = [c for c in calls if c["enclosing_function_id"] == f["id"]]
    hk = [(c['name'], c.get('dispatch_type'), len(c.get('candidate_target_ids',[]))) for c in bc if c['name']=='HandleOKCallback']
    print(f"  DoComplete id={f['id']} -> HandleOKCallback calls: {hk}")
