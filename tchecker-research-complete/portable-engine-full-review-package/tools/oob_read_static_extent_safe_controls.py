#!/usr/bin/env python3
"""B4.7R STATIC_EXTENT_SAFE regression controls for oob_read_verdict.py (task #43).

Self-contained, no external fixture. Motivated by a real re2 site found while fixing #29:
RoundTripFloatToBuffer:804 -- memcpy(out, spec->expstr, 4) with a real capacity_bytes=5 for
spec->expstr -- 4<=5 is statically safe, yet the scanner reported it as verdict=CANDIDATE before
this fix. Covers: the real re2 case itself (as a synthetic reconstruction), the exact boundary
(literal == capacity), the unsafe direction (literal > capacity, must stay a candidate -- no false
negatives introduced), non-literal extents (must be unaffected), the sizeof(src) form, a sizeof of
the WRONG identifier (must NOT be suppressed), and conservative non-matches (hex/suffixed
literals) that intentionally stay CANDIDATE rather than risk a wrong classification.
"""
import json, sys, pathlib, tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from oob_read_verdict import emit_candidates, is_static_extent_safe

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)

# --- unit-level checks on is_static_extent_safe() directly ---
ck("unit: literal 4 <= capacity 5 -> safe", is_static_extent_safe('spec->expstr', '4', 'LITERAL', 5))
ck("unit: literal 5 == capacity 5 (boundary) -> safe", is_static_extent_safe('spec->expstr', '5', 'LITERAL', 5))
ck("unit: literal 6 > capacity 5 -> NOT safe (no false negative)", not is_static_extent_safe('spec->expstr', '6', 'LITERAL', 5))
ck("unit: sizeof(src) matching source identifier -> safe", is_static_extent_safe('buf', 'sizeof(buf)', 'CALL', 16))
ck("unit: sizeof(other) NOT matching source identifier -> NOT safe", not is_static_extent_safe('buf', 'sizeof(other)', 'CALL', 16))
ck("unit: non-literal, non-sizeof extent (variable) -> NOT safe", not is_static_extent_safe('buf', 'n', 'IDENTIFIER', 16))
ck("unit: hex literal '0x4' -> conservatively NOT recognized (stays candidate)", not is_static_extent_safe('buf', '0x4', 'LITERAL', 16))
ck("unit: suffixed literal '4u' -> conservatively NOT recognized (stays candidate)", not is_static_extent_safe('buf', '4u', 'LITERAL', 16))
ck("unit: kind is not LITERAL even though code looks numeric -> NOT safe", not is_static_extent_safe('buf', '4', 'IDENTIFIER', 16))
ck("unit: capacity_bytes is None -> NOT safe (no crash, no false suppression)", not is_static_extent_safe('buf', '4', 'LITERAL', None))

# --- end-to-end check against emit_candidates(), reconstructing the real re2 shape ---
with tempfile.TemporaryDirectory() as td:
    pref = str(pathlib.Path(td) / "g.json")
    facts = {
        "functions": [{"id": 1, "name": "RoundTripFloatToBuffer"}],
        "calls": [
            # The real re2 site: memcpy(out, spec->expstr, 4), capacity(spec->expstr)=5.
            {"id": 804, "name": "memcpy", "line": 804, "enclosing_function_id": 1,
             "arguments": [{"index": 0, "value_ref": {"id": 1}},
                           {"index": 1, "value_ref": {"id": -1, "code": "spec->expstr"}},
                           {"index": 2, "kind": "LITERAL", "value_ref": {"id": -1, "code": "4"}}]},
            # A sibling site with the SAME field capacity but an unsafe literal (6 > 5) -- must
            # remain a real candidate; the fix must not overreach.
            {"id": 900, "name": "memcpy", "line": 900, "enclosing_function_id": 1,
             "arguments": [{"index": 0, "value_ref": {"id": 2}},
                           {"index": 1, "value_ref": {"id": -1, "code": "spec->expstr"}},
                           {"index": 2, "kind": "LITERAL", "value_ref": {"id": -1, "code": "6"}}]},
        ],
    }
    roles = {"operand_roles": [
        {"id": 804, "role": "READ_SRC", "operand_index": 1},
        {"id": 804, "role": "EXTENT", "operand_index": 2},
        {"id": 900, "role": "READ_SRC", "operand_index": 1},
        {"id": 900, "role": "EXTENT", "operand_index": 2},
    ]}
    srccap = {"src_capacities": [
        {"storage_identity_kind": "FIELD", "storage_value_id": -1, "call_id": 804, "capacity_bytes": 5,
         "field_storage_key": "FIELD:1:2"},
        {"storage_identity_kind": "FIELD", "storage_value_id": -1, "call_id": 900, "capacity_bytes": 5,
         "field_storage_key": "FIELD:1:2"},
    ]}
    bounds = {"bounds": []}

    json.dump(facts, open(pref, "w"))
    json.dump(roles, open(pref + ".operandrole.json", "w"))
    json.dump(srccap, open(pref + ".srccapacity.json", "w"))
    json.dump(bounds, open(pref + ".bound.json", "w"))

    cands = emit_candidates(pref)
    by_line = {c["line"]: c for c in cands}

    ck("e2e: real re2 shape (4<=5) is suppressed, not a candidate", 804 not in by_line)
    ck("e2e: sibling unsafe site (6>5) remains a real candidate", 900 in by_line and by_line[900]["src_capacity_bytes"] == 5)
    ck("e2e: total candidates == 1 (only the genuinely unsafe site)", len(cands) == 1)

print(f"OOB_READ_STATIC_EXTENT_SAFE_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
