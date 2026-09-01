#!/usr/bin/env python3
"""PROV-RECONCILE-R01 controls: conservative source-path reconciliation against the FULL
package-root manifest (never a narrowed pkg_dir). Pure path-string logic -- no Joern
facts needed for the synthetic controls; the real leveldb full-package-root run is
exercised separately by check_napi_export_root/the combined pipeline re-run.
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import napi_status_integration as integ  # noqa: E402

ok = total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- 1. exact package-relative path -----------------------------------------------------
manifest = {"src/bindings.cpp": {}, "README.md": {}, "package.json": {}}
resolved, ambiguous = integ.reconcile_source_path("src/bindings.cpp", manifest)
ck("exact path: 'src/bindings.cpp' resolves to itself, not ambiguous",
   resolved == "src/bindings.cpp" and not ambiguous)

# --- 2. unique suffix (basename-only field) ---------------------------------------------
resolved, ambiguous = integ.reconcile_source_path("bindings.cpp", manifest)
ck("unique suffix: bare basename 'bindings.cpp' resolves to the one real "
   "'src/bindings.cpp', canonical path stored",
   resolved == "src/bindings.cpp" and not ambiguous)

resolved, ambiguous = integ.reconcile_source_path("cpp/db.cpp", {
    "src/leveldown/cpp/db.cpp": {}, "other.cpp": {}})
ck("unique suffix: a shortened multi-component suffix resolves to the one real match",
   resolved == "src/leveldown/cpp/db.cpp" and not ambiguous)

# --- 3. duplicate basenames -> ABSTAIN ---------------------------------------------------
dup_manifest = {"src/bindings.cpp": {}, "vendor/leveldb/bindings.cpp": {}}
resolved, ambiguous = integ.reconcile_source_path("bindings.cpp", dup_manifest)
ck("duplicate basenames: two real files share 'bindings.cpp' -> ABSTAIN "
   "(never guesses which one)",
   resolved is None and ambiguous is True)

# --- 4. normalized separators ------------------------------------------------------------
resolved, ambiguous = integ.reconcile_source_path("src\\bindings.cpp", manifest)
ck("normalized separators: a backslash-spelled field still resolves exactly",
   resolved == "src/bindings.cpp" and not ambiguous)
resolved, ambiguous = integ.reconcile_source_path("./src/bindings.cpp", manifest)
ck("normalized separators: a leading './' is stripped before matching",
   resolved == "src/bindings.cpp" and not ambiguous)

# --- 5. unmatched paths -> unresolved (not ambiguous, not resolved) ---------------------
resolved, ambiguous = integ.reconcile_source_path("nowhere/missing.cpp", manifest)
ck("unmatched path: zero real files match -> unresolved, NOT flagged ambiguous "
   "(falls through to the normal PATH_NOT_IN_MANIFEST reason)",
   resolved is None and ambiguous is False)

# --- suffix match must not cross a component boundary wrongly ---------------------------
tricky = {"src/xbindings.cpp": {}, "src/bindings.cpp": {}}
resolved, ambiguous = integ.reconcile_source_path("bindings.cpp", tricky)
ck("suffix match is component-exact: 'bindings.cpp' does not spuriously match "
   "'xbindings.cpp' (only the real 'src/bindings.cpp')",
   resolved == "src/bindings.cpp" and not ambiguous)

# --- full _reconcile_method_file_map + enrich_napi_status wiring, incl. the ambiguous
# override forcing resolved=False with the exact reason -------------------------------
mfm = {1: "bindings.cpp", 2: "bindings.cpp", 3: "missing.cpp"}
manifest_files = {"src/bindings.cpp": {"content_hash": "abc", "provenance_hint": "x"},
                  "vendor/other/bindings.cpp": {"content_hash": "def",
                                                "provenance_hint": "x"}}
reconciled, amb_ids = integ._reconcile_method_file_map(mfm, manifest_files)
ck("_reconcile_method_file_map: duplicate-basename ids land in ambiguous_ids",
   amb_ids == {1, 2})
ck("_reconcile_method_file_map: the unmatched id is untouched (still the raw field, "
   "not marked ambiguous)",
   3 not in amb_ids and reconciled[3] == "missing.cpp")

record = {integ.NAPI_STATUS_KEY: [
    {"method_id": 1, "verdict": "STATUS_GUARD_MISSING",
     "sub_reason": "STATUS_DISCARDED", "method_name": "x", "file": "f", "line": "1",
     "creation_call_name": "napi_create_buffer"}]}
full_manifest = {"package_name": "p", "version": "1", "tarball_sha256": None,
                 "source_tree_sha256": "full-tree-hash", "files": manifest_files}


class _FakeRaw:
    """Minimal stand-in so provenance.load_method_file_map() sees the dup-basename map
    without needing real methods.tsv on disk."""


import provenance as _prov  # noqa: E402
_orig_load = _prov.load_method_file_map
_prov.load_method_file_map = lambda cpp_raw_dir: mfm
try:
    integ.enrich_napi_status(record, "unused", full_manifest, "unused")
finally:
    _prov.load_method_file_map = _orig_load
f0 = record[integ.NAPI_STATUS_KEY][0]
ck("end-to-end: a finding whose function id has a duplicate-basename source path is "
   "forced provenance.resolved=False with provenance_hint=AMBIGUOUS_SOURCE_PATH",
   f0["provenance"]["resolved"] is False
   and f0["provenance"]["provenance_hint"] == "AMBIGUOUS_SOURCE_PATH"
   and f0["provenance"]["source_path"] is None)
ck("end-to-end: source_tree_sha256 on the finding is the FULL-package-root hash "
   "(never recomputed over a narrowed subdirectory)",
   f0["provenance"]["source_tree_sha256"] == "full-tree-hash")
ck("end-to-end: an ambiguous/unresolved finding can never be reportable",
   f0.get("reportable") is False)

print(f"PROV_RECONCILE_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
