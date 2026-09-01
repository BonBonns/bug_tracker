#!/usr/bin/env python3
"""NAPI-STATUS real-package positive-path regression: @8crafter/leveldb-zlib@1.6.0.

This is the first REAL package to exercise the property's positive path
(STATUS_GUARD_MISSING), found by the targeted 10-package validation
(study/napi_status/VALIDATION_10_FROZEN.json) and MANUALLY REVIEWED against the real
pinned source (package/src/bindings.cpp): two napi_create_buffer_copy calls that
discard their napi_status and use the required output immediately afterward at
napi_set_element, plus one correct abstention where the output goes into an array
element. study/napi_status/fixture_leveldb_real.cpp is those two real methods copied
verbatim (types stubbed to compile hermetically); study/napi_status/raw_leveldb_real/
is its frozen real Joern v4.0.608 facts.

Pinning this is what justifies flipping NAPI_STATUS_ENABLED to True: the class is no
longer fixtures-only. Every expectation is an API-handling classification; none is a
vulnerability or impact claim.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "napi_status_verdict_r02.py"
RAW = HERE / "study" / "napi_status" / "raw_leveldb_real"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


outpath = HERE / "study" / "napi_status" / "out_leveldb_real.json"
subprocess.run([sys.executable, str(CAP), str(RAW), str(outpath)], check=True,
               stdout=subprocess.DEVNULL)
r = json.loads(outpath.read_text())
c = r["classification"]

ck("three supported napi_create_buffer_copy sites recognized (matches the real "
   "package's own 3-site HandleOKCallback pattern)",
   c.get("SUPPORTED_CREATION_CALL_FOUND") == 3)
ck("exactly two STATUS_GUARD_MISSING positive-path findings",
   c.get("STATUS_GUARD_MISSING") == 2)
ck("exactly one ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED (the &argv[1] array-element "
   "destination -- correctly neither flagged nor cleared)",
   c.get("ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED") == 1)

gm = [f for f in r["findings"] if f["verdict"] == "STATUS_GUARD_MISSING"]
ck("both positive findings are STATUS_DISCARDED (the status return is dropped, not "
   "checked)",
   len(gm) == 2 and all(f.get("sub_reason") == "STATUS_DISCARDED" for f in gm))
ck("both positive findings cite the required output (returnKey / returnValue) as the "
   "unguarded use, and each records the optional result_data NULL opt-out",
   {f.get("unguarded_use_variable") for f in gm} == {"returnKey", "returnValue"}
   and all(any(t.get("opted_out") and t["role"] == "result_data"
               for t in f.get("output_targets", [])) for f in gm)
   and all(any(t.get("required") and t["role"] == "result" for t in
               f.get("output_targets", [])) for f in gm))
ck("both positive findings carry a real unguarded-use line and node id (evidence, "
   "not just a verdict)",
   all(f.get("unguarded_use_line") and f.get("unguarded_use_node") for f in gm))
ck("no vulnerability language in the output (claims-boundary lint)",
   "vulnerab" not in json.dumps(r).lower())

print(f"NAPI_STATUS_LEVELDB_REGRESSION={ok}/{total}")
sys.exit(0 if ok == total else 1)
