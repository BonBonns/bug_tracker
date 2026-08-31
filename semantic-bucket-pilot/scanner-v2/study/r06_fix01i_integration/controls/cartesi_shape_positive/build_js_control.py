#!/usr/bin/env python3
"""R06/FIX01I integration -- DISCLOSED SYNTHETIC control, NOT a real corpus finding.

Writes ONE synthetic JS call (`machine.readMemory(address, length)`, 2 real arguments) into
a minimal, real-shaped `js_facts_adapted.json`, matching Cartesi's own real published
package's field schema exactly (confirmed real via `/tmp/smoke_test_cartesi/work/
js_facts_adapted.json`) -- so `promote_via_js_linkage.py`'s full promotion chain can be
proven end-to-end against Cartesi's OWN real C++ facts (`/tmp/cartesi_raw`,
`/tmp/smoke_test_cartesi/work/cpp_facts.json` -- NOT synthetic, already independently
verified real) while the JS-CALL-SITE half is a disclosed synthetic addition, since
Cartesi's own real, currently-published `dist/index.cjs` is a WASM/minified bundle that does
NOT contain a real call naming `readMemory` anywhere (confirmed by direct inspection --
see R06_FIX01I_INTEGRATION.md). This control exists ONLY to prove the mechanism is correct
when genuine JS-linkage evidence IS present -- it must never be cited as a real Cartesi
corpus finding.
"""
import json

js_doc = {
    "schema": "portable-program-facts/0.2",
    "frontend": "synthetic-control (see this file's own module docstring)",
    "calls": [
        {
            "id": 900000001,
            "name": "readMemory",
            "code": "machine.readMemory(address, length)",
            "receiver_name": "bindings",
            "receiver_type": None,
            "resolution": "UNRESOLVED",
            "enclosing_function_id": 900000000,
            "candidate_target_ids": [],
            "candidate_target_full_names": [],
            "arguments": [
                {"index": 1, "kind": "IDENTIFIER", "code": "address", "name": "address",
                 "id": 900000002, "call_id": 900000001, "type_full_name": "ANY", "line": 1},
                {"index": 2, "kind": "IDENTIFIER", "code": "length", "name": "length",
                 "id": 900000003, "call_id": 900000001, "type_full_name": "ANY", "line": 1},
            ],
        }
    ],
    "functions": [], "identifiers": [], "locals": [], "members": [],
    "method_returns": [], "returns": [], "type_decls": [], "metadata": [],
}

if __name__ == "__main__":
    with open("js_facts_adapted.json", "w") as f:
        json.dump(js_doc, f, indent=2)
    print("wrote js_facts_adapted.json (synthetic control -- see module docstring)")
