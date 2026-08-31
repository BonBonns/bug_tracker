#!/usr/bin/env python3
"""CAP-KEY-R01 regression controls for oob_read_verdict.py (task #29).

Self-contained: unlike oob_read_controls.py / oob_write_controls.py, this does
NOT depend on an external /tmp/cap_corpus/*.json fixture built by some earlier,
un-tracked c2cpg run -- it builds its own minimal synthetic fact bundle inline,
so it stays runnable from a clean checkout.

Root cause under test: oob_read_verdict.py used to join source-capacity facts
to a read site with a single dict keyed by storage_value_id ONLY:
    scap={f['storage_value_id']:f for f in ...}
A field access (e.g. `p->buf`) collapses storage_value_id to the sentinel -1.
Since -1 is not a real identity, EVERY read site whose own field-identity
resolution also failed (also -1) collided on whichever ONE FIELD-kind fact
happened to exist in the file, regardless of function or call site -- this is
exactly what produced the uniform, bogus src_capacity_bytes=5 across 6 of 7
unrelated real OOB_READ candidates on a real re2 package build. The fix mirrors
the dcap/dcap_by_call split already correct in oob_write_verdict.py: FIELD
facts join by call_id (unique per site); VALUE_ID facts join by
storage_value_id (>=0 only).
"""
import json, sys, pathlib, tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from oob_read_verdict import emit_candidates

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)

with tempfile.TemporaryDirectory() as td:
    pref = str(pathlib.Path(td) / "g.json")
    facts = {
        "functions": [{"id": 1, "name": "f"}],
        "calls": [
            # VALUE_ID-identified source, unbounded -> must remain a candidate (regression check).
            {"id": 100, "name": "memcpy", "line": 10, "enclosing_function_id": 1,
             "arguments": [{"index": 0, "value_ref": {"id": 900}},
                           {"index": 1, "value_ref": {"id": 7}},
                           {"index": 2, "value_ref": {"id": 901}}]},
            # FIELD-identified source (svid=-1) at THIS call_id -> the real fact for THIS
            # site -> must resolve as a candidate.
            {"id": 200, "name": "memcpy", "line": 20, "enclosing_function_id": 1,
             "arguments": [{"index": 0, "value_ref": {"id": 902}},
                           {"index": 1, "value_ref": {"id": -1}},
                           {"index": 2, "value_ref": {"id": 903}}]},
            # FIELD-identified source (svid=-1) at a DIFFERENT call_id, with no FIELD fact
            # of its own -> must abstain (this is the exact bug: it used to spuriously
            # match call 200's fact via the shared sentinel key -1).
            {"id": 300, "name": "memcpy", "line": 30, "enclosing_function_id": 1,
             "arguments": [{"index": 0, "value_ref": {"id": 904}},
                           {"index": 1, "value_ref": {"id": -1}},
                           {"index": 2, "value_ref": {"id": 905}}]},
            # VALUE_ID source, validly SOURCE_CAPACITY-bounded on its extent -> not a candidate.
            {"id": 400, "name": "memcpy", "line": 40, "enclosing_function_id": 1,
             "arguments": [{"index": 0, "value_ref": {"id": 906}},
                           {"index": 1, "value_ref": {"id": 8}},
                           {"index": 2, "value_ref": {"id": 907}}]},
        ],
    }
    roles = {"operand_roles": [
        {"id": 100, "role": "READ_SRC", "operand_index": 1},
        {"id": 100, "role": "EXTENT", "operand_index": 2},
        {"id": 200, "role": "READ_SRC", "operand_index": 1},
        {"id": 200, "role": "EXTENT", "operand_index": 2},
        {"id": 300, "role": "READ_SRC", "operand_index": 1},
        {"id": 300, "role": "EXTENT", "operand_index": 2},
        {"id": 400, "role": "READ_SRC", "operand_index": 1},
        {"id": 400, "role": "EXTENT", "operand_index": 2},
    ]}
    srccap = {"src_capacities": [
        {"storage_identity_kind": "VALUE_ID", "storage_value_id": 7, "capacity_bytes": 16, "call_id": 100},
        {"storage_identity_kind": "FIELD", "storage_value_id": -1, "call_id": 200, "capacity_bytes": 5,
         "field_storage_key": "FIELD:1:2"},
        {"storage_identity_kind": "VALUE_ID", "storage_value_id": 8, "capacity_bytes": 32, "call_id": 400},
    ]}
    bounds = {"bounds": [{"checked_value_id": 907, "bound_side": "SOURCE_CAPACITY"}]}

    json.dump(facts, open(pref, "w"))
    json.dump(roles, open(pref + ".operandrole.json", "w"))
    json.dump(srccap, open(pref + ".srccapacity.json", "w"))
    json.dump(bounds, open(pref + ".bound.json", "w"))

    cands = emit_candidates(pref)
    by_line = {c["line"]: c for c in cands}

    ck("VALUE_ID join still works (regression check): line 10 candidate, src_cap=16",
       10 in by_line and by_line[10]["src_capacity_bytes"] == 16)
    ck("FIELD join at matching call_id (line 20) is a candidate, src_cap=5",
       20 in by_line and by_line[20]["src_capacity_bytes"] == 5)
    ck("FIELD sentinel no longer spuriously matches a DIFFERENT call_id (line 30 abstains)",
       30 not in by_line)
    ck("VALUE_ID site with a valid SOURCE_CAPACITY bound on extent is suppressed (line 40 not a candidate)",
       40 not in by_line)
    ck("total candidates == 2 (lines 10 and 20 only)", len(cands) == 2)

print(f"OOB_READ_CAPKEY_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
