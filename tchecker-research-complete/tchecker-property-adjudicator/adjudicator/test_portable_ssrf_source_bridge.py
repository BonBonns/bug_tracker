#!/usr/bin/env python3
import copy
import portable_ssrf_source_bridge as bridge

ok = total = 0
def ck(name, condition):
    global ok, total
    total += 1; ok += bool(condition)
    print(("PASS " if condition else "FAIL ") + name)

def fact(node=200, location="tabs.onUpdated.tab.url"):
    return {"id": node, "function_id": 10, "target_local_id": node,
            "target_kind": "STATE_READ", "origin_kind": "WEBEXT_TAB_URL_INPUT",
            "location": location,
            "derivation": {"origin": "FRONTEND_COMPOSED",
                           "rule": "JS_WEBEXT_TAB_URL_SOURCE",
                           "source_node_ids": [100, 11, node]}}

def external_fact(registration=300, parameter=21):
    return {"id": registration, "function_id": 20, "target_local_id": parameter,
            "target_kind": "PARAMETER", "origin_kind": "WEBEXT_EXTERNAL_MESSAGE_INPUT",
            "location": "runtime.onMessageExternal",
            "derivation": {"origin": "FRONTEND_COMPOSED",
                           "rule": "JS_WEBEXT_EXTERNAL_MESSAGE_SOURCE",
                           "source_node_ids": [registration, 120, parameter]}}

base = {"schema": "portable-source-facts/0.1", "source_origins": [
    fact(),
    external_fact(),
]}
rows = bridge.derive(base)
ck("tab URL state read crosses the bridge",
   (200, "WEBEXT_TAB_URL_INPUT", "STATE_READ", "tabs.onUpdated.tab.url") in rows)
ck("external runtime payload parameter crosses as its own class",
   (21, "WEBEXT_EXTERNAL_MESSAGE_INPUT", "PARAMETER", "runtime.onMessageExternal") in rows)
ck("tab URL and external-message families remain distinct", len(rows) == 2 and rows[0][1] != rows[1][1])

for name, mutate in [
    ("wrong target kind fails closed", lambda d: d["source_origins"][0].update(target_kind="PARAMETER")),
    ("fabricated target identity fails closed", lambda d: d["source_origins"][0].update(id=201)),
    ("unsupported event location fails closed", lambda d: d["source_origins"][0].update(location="tabs.onActivated.tab.url")),
    ("wrong derivation fails closed", lambda d: d["source_origins"][0]["derivation"].update(rule="NAME_MATCH")),
    ("schema drift fails closed", lambda d: d.update(schema="portable-source-facts/9.9")),
]:
    doc = copy.deepcopy(base); mutate(doc)
    try: bridge.derive(doc)
    except ValueError: rejected = True
    else: rejected = False
    ck(name, rejected)

dup = copy.deepcopy(base); dup["source_origins"].append(fact())
try: bridge.derive(dup)
except ValueError: rejected = True
else: rejected = False
ck("duplicate target facts fail closed", rejected)
ck("all three frozen URL locations are accepted",
   all(bridge.derive({"schema": bridge.SCHEMA, "source_origins": [fact(i + 1, loc)]})
       for i, loc in enumerate(sorted(bridge.LOCATIONS))))

for name, mutate in [
    ("external wrong target kind fails closed", lambda d: d["source_origins"][0].update(target_kind="STATE_READ")),
    ("external internal-message location fails closed", lambda d: d["source_origins"][0].update(location="runtime.onMessage")),
    ("external wrong derivation fails closed", lambda d: d["source_origins"][0]["derivation"].update(rule="NAME_MATCH")),
    ("external missing parameter identity fails closed", lambda d: d["source_origins"][0]["derivation"].update(source_node_ids=[300, 120])),
    ("external registration and parameter identities cannot collapse", lambda d: d["source_origins"][0].update(id=21)),
]:
    doc = {"schema": bridge.SCHEMA, "source_origins": [external_fact()]}
    mutate(doc)
    try: bridge.derive(doc)
    except ValueError: rejected = True
    else: rejected = False
    ck(name, rejected)

unknown = {"schema": bridge.SCHEMA, "source_origins": [{
    "id": 1, "target_local_id": 2, "target_kind": "PARAMETER",
    "origin_kind": "HTTP_BODY", "location": "express.body", "derivation": {}}]}
ck("unrelated source families remain outside this bridge", bridge.derive(unknown) == [])

print(f"PORTABLE_SSRF_BRIDGE_CONTROLS={ok}/{total}")
raise SystemExit(0 if ok == total else 1)
