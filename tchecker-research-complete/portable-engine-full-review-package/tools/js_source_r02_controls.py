#!/usr/bin/env python3
"""JS-SOURCE-R02 source-class and contamination controls (no Joern needed)."""
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

def fn(fid, pid, name="handler"):
    return {"id": fid, "name": name, "full_name": f"x.js::program:{name}",
            "is_external": False,
            "parameters": [{"id": pid, "index": 0, "name": "message"}]}

def listener(cid, owner, ref, code):
    return {"id": cid, "name": "addListener", "code": code,
            "enclosing_function_id": owner,
            "arguments": [{"id": cid + 1000, "index": 0, "value_ref": ref}]}

methods = [fn(10, 11, "inline"), fn(20, 21, "named"), fn(30, 31, "ambiguous")]
calls = [
    listener(100, 1, {"kind": "FUNCTION", "id": 10},
             "browser.runtime.onMessageExternal.addListener(msg => use(msg))"),
    listener(101, 1, {"kind": "LOCAL", "id": 50},
             "chrome . runtime . onMessageExternal . addListener(named)"),
    listener(102, 1, {"kind": "FUNCTION", "id": 10},
             "browser.runtime.onMessage.addListener(msg => use(msg))"),
    listener(103, 1, {"kind": "FUNCTION", "id": 10},
             "browser.tabs.onUpdated.addListener((id, change, tab) => use(tab))"),
    listener(104, 1, {"kind": "FUNCTION", "id": 10},
             "browser.test.onMessageExternal.addListener(msg => use(msg))"),
    listener(105, 1, {"kind": "FUNCTION", "id": 10},
             "evilbrowser.runtime.onMessageExternal.addListener(msg => use(msg))"),
    listener(106, 1, {"kind": "LOCAL", "id": 60},
             "browser.runtime.onMessageExternal.addListener(maybeHandler)"),
]
assignments = [
    {"function_id": 1, "target_local_id": 50, "value_ref": {"kind": "FUNCTION", "id": 20}},
    {"function_id": 1, "target_local_id": 60, "value_ref": {"kind": "FUNCTION", "id": 30}},
    {"function_id": 1, "target_local_id": 60, "value_ref": {"kind": "FUNCTION", "id": 10}},
]
facts = mod.derive_webext_external_message_sources(methods, calls, assignments)
by_event = {f["id"]: f for f in facts}
ck("direct browser external listener recognized", 100 in by_event)
ck("named chrome handler recognized through one exact local definition", 101 in by_event)
ck("ordinary runtime.onMessage remains a separate class", 102 not in by_event)
ck("tabs.onUpdated metadata remains a separate class", 103 not in by_event)
ck("browser.test harness does not contaminate runtime sources", 104 not in by_event)
ck("identifier-prefix collision does not match", 105 not in by_event)
ck("multiply-defined handler local abstains", 106 not in by_event)
ck("only the payload parameter (index 0) is targeted",
   all(f["target_local_id"] in (11, 21) for f in facts))
ck("origin kind remains WebExtension-specific",
   all(f["origin_kind"] == "WEBEXT_EXTERNAL_MESSAGE_INPUT" for f in facts))
ck("derivation is composed and auditable",
   all(f["derivation"]["rule"] == "JS_WEBEXT_EXTERNAL_MESSAGE_SOURCE"
       and len(f["derivation"]["source_node_ids"]) == 3 for f in facts))
print(f"JS_SOURCE_R02_CONTROLS={ok}/{total}")
raise SystemExit(0 if ok == total else 1)
