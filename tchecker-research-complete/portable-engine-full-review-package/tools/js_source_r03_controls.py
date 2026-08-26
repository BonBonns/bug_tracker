#!/usr/bin/env python3
"""JS-SOURCE-R03 tab-URL source and contamination controls (no Joern needed)."""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
NORMALIZER = HERE.parent / "frontends" / "javascript-typescript" / "joern-ts" / "normalize_ts_facts.py"
spec = importlib.util.spec_from_file_location("normalize_ts_facts", NORMALIZER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

ok = total = 0
def ck(name, condition):
    global ok, total
    total += 1; ok += bool(condition)
    print(("PASS " if condition else "FAIL ") + name)

def fn(fid, params, name):
    return {"id": fid, "name": name, "full_name": f"x.js::program:{name}",
            "is_external": False,
            "parameters": [{"id": pid, "index": i, "name": pname}
                           for i, (pid, pname) in enumerate(params)]}

def listener(cid, ref, code):
    return {"id": cid, "name": "addListener", "code": code,
            "enclosing_function_id": 1,
            "arguments": [{"id": cid + 1000, "index": 0, "value_ref": ref}]}

def read(rid, fid, pid, key, path=None):
    return {"index_call_id": rid, "function_id": fid,
            "receiver_location": {"root_ref": {"kind": "PARAMETER", "id": pid},
                                  "path": [] if path is None else path},
            "key": {"kind": "LITERAL", "value": key}}

methods = [
    fn(10, [(11, "tab")], "created"),
    fn(20, [(21, "tabId"), (22, "changeInfo"), (23, "tab")], "updated"),
    fn(30, [(31, "tab")], "named"),
    fn(40, [(41, "tab")], "ambiguous"),
]
calls = [
    listener(100, {"kind": "FUNCTION", "id": 10},
             "browser.tabs.onCreated.addListener(tab => use(tab.url))"),
    listener(101, {"kind": "FUNCTION", "id": 20},
             "chrome . tabs . onUpdated . addListener((id, change, tab) => use(change.url, tab.url))"),
    listener(102, {"kind": "FUNCTION", "id": 10},
             "browser.runtime.onMessage.addListener(tab => use(tab.url))"),
    listener(103, {"kind": "FUNCTION", "id": 10},
             "browser.test.tabs.onCreated.addListener(tab => use(tab.url))"),
    listener(104, {"kind": "FUNCTION", "id": 10},
             "evilbrowser.tabs.onCreated.addListener(tab => use(tab.url))"),
    listener(105, {"kind": "FUNCTION", "id": 10},
             "api.tabs.onCreated.addListener(tab => use(tab.url))"),
    listener(106, {"kind": "LOCAL", "id": 50},
             "browser.tabs.onCreated.addListener(named)"),
    listener(107, {"kind": "LOCAL", "id": 60},
             "browser.tabs.onCreated.addListener(maybeHandler)"),
]
assignments = [
    {"function_id": 1, "target_local_id": 50,
     "value_ref": {"kind": "FUNCTION", "id": 30}},
    {"function_id": 1, "target_local_id": 60,
     "value_ref": {"kind": "FUNCTION", "id": 40}},
    {"function_id": 1, "target_local_id": 60,
     "value_ref": {"kind": "FUNCTION", "id": 10}},
]
state_reads = [
    read(200, 10, 11, "url"),
    read(201, 10, 11, "id"),
    read(202, 10, 11, "cookieStoreId"),
    read(203, 10, 11, "url", [{"kind": "LITERAL", "value": "nested"}]),
    read(210, 20, 21, "url"),
    read(211, 20, 22, "url"),
    read(212, 20, 22, "status"),
    read(213, 20, 23, "url"),
    read(214, 20, 23, "id"),
    read(230, 30, 31, "url"),
    read(240, 40, 41, "url"),
]

facts = mod.derive_webext_tab_url_sources(methods, calls, assignments, state_reads)
by_read = {f["target_local_id"]: f for f in facts}
ck("onCreated tab.url read recognized", 200 in by_read)
ck("onUpdated changeInfo.url and tab.url reads recognized", {211, 213} <= set(by_read))
ck("tab id, cookieStoreId, change status, and callback tabId remain separate",
   not ({201, 202, 210, 212, 214} & set(by_read)))
ck("nested foo.url is not flattened into tab.url", 203 not in by_read)
ck("ordinary runtime messages do not become tab URL sources",
   len([f for f in facts if f["derivation"]["source_node_ids"][0] == 102]) == 0)
ck("test, prefix-collision, and aliased namespaces do not match",
   not ({103, 104, 105} & {f["derivation"]["source_node_ids"][0] for f in facts}))
ck("exactly-defined named handler is supported", 230 in by_read)
ck("multiply-defined handler local abstains", 240 not in by_read)
ck("facts target individual state reads, not entire parameters",
   all(f["target_kind"] == "STATE_READ" and f["id"] == f["target_local_id"] for f in facts))
ck("tab URL origin kind is distinct and derivation is auditable",
   all(f["origin_kind"] == "WEBEXT_TAB_URL_INPUT"
       and f["derivation"]["rule"] == "JS_WEBEXT_TAB_URL_SOURCE"
       and len(f["derivation"]["source_node_ids"]) == 3 for f in facts))
ck("only the four intended controlled reads are emitted",
   set(by_read) == {200, 211, 213, 230})

print(f"JS_SOURCE_R03_CONTROLS={ok}/{total}")
raise SystemExit(0 if ok == total else 1)
