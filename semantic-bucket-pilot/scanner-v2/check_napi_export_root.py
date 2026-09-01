#!/usr/bin/env python3
"""NAPI-EXPORT-ROOT-R01 control gate. Controls 1-10 over the compiled
fixture_export_root.cpp (frozen raw_export_root/); controls 11-12 over the REAL
header-expanded leveldb-zlib facts (frozen raw_leveldb_export_hdr/, produced by staging
node headers so NAPI_EXPORT_FUNCTION expands). Recognizer keys on N-API calls and
argument identities only -- never macro spelling, source text, or a function name.
Reachability structure; no security or runtime claim."""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import napi_export_root as E  # noqa: E402

STUDY = HERE / "study" / "napi_status"
ok = total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def analyze(rawdir):
    roots, abstained, F = E.established_roots(str(STUDY / rawdir))
    est = {ev["function"].split(":", 1)[0] for ev in roots.values()}
    reasons = [a["reason"] for a in abstained]
    return est, reasons, roots


# --- Controls 1-10 (compiled fixture) ---------------------------------------------------
est, reasons, roots = analyze("raw_export_root")

ck("C1 exact create-function -> same-value set-property -> returned exports: cb1 "
   "ESTABLISHED", "cb1" in est)
ck("C1 and it is the ONLY thing established (no over-recognition)", est == {"cb1"})
ck("C2 created function never attached: cb2 NOT established",
   "cb2" not in est)
ck("C3 a DIFFERENT napi_value attached: cb3 NOT established, "
   "ATTACHED_VALUE_NOT_FROM_CREATE_FUNCTION recorded",
   "cb3" not in est and "ATTACHED_VALUE_NOT_FROM_CREATE_FUNCTION" in reasons)
ck("C4 property attached to a different object: cb4 NOT established, "
   "EXPORTS_NOT_RETURNED_BY_MODULE_INIT recorded",
   "cb4" not in est and "EXPORTS_NOT_RETURNED_BY_MODULE_INIT" in reasons)
ck("C5 ambiguous callback identity: amb NOT established, AMBIGUOUS_CALLBACK_IDENTITY "
   "recorded",
   "amb" not in est and "AMBIGUOUS_CALLBACK_IDENTITY" in reasons)
ck("C6 callback argument is not a method reference: cb6 NOT established, "
   "CALLBACK_NOT_A_METHOD_REF recorded",
   "cb6" not in est and "CALLBACK_NOT_A_METHOD_REF" in reasons)
ck("C7 registration outside a proven module initializer: cb7 NOT established",
   "cb7" not in est)
ck("C8 initializer returns a different exports object: cb8 NOT established",
   "cb8" not in est)
ck("C9 multiple created-function definitions reach the property call: cb9a/cb9b NOT "
   "established, MULTIPLE_CREATE_FUNCTION_DEFS_REACH_PROPERTY recorded",
   "cb9a" not in est and "cb9b" not in est
   and "MULTIPLE_CREATE_FUNCTION_DEFS_REACH_PROPERTY" in reasons)
ck("C10 unresolved napi_define_properties: explicit UNRESOLVED_DEFINE_PROPERTIES_IDIOM "
   "abstention",
   "UNRESOLVED_DEFINE_PROPERTIES_IDIOM" in reasons)
ck("C1-10 never-exported callback (cb_never_exported) is NOT established",
   "cb_never_exported" not in est)

# --- Controls 11-12 (REAL header-expanded leveldb) -------------------------------------
lev_est, lev_reasons, lev_roots = analyze("raw_leveldb_export_hdr")

ck("C11 real header-expanded leveldb registration: iterator_next ESTABLISHED",
   "iterator_next" in lev_est)
ck("C11 established via the one-hop module-init wrapper (module_init proven, not guessed)",
   any(ev["function"].startswith("iterator_next")
       and ev["module_init_evidence"]["kind"] in ("one_hop_wrapper", "attach_function_is_init")
       for ev in lev_roots.values()))
ck("C11 the other real exports are established too (db_get, batch_write) and it is "
   "not a coincidence of one name",
   {"db_get", "batch_write"} <= lev_est)
ck("C12 a real function in the same package that is never exported "
   "(CreateError) is NOT established",
   "CreateError" not in lev_est)
ck("C12 the module initializer itself (napi_macros_init) is NOT established as a root",
   "napi_macros_init" not in lev_est)
ck("C12 a worker override (NextWorker::HandleOKCallback) is NOT an export root "
   "(it is reached by virtual dispatch, not by direct export)",
   not any("HandleOKCallback" in ev["function"] for ev in lev_roots.values()))

print(f"NAPI_EXPORT_ROOT_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
