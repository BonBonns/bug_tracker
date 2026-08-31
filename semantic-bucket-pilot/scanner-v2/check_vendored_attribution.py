#!/usr/bin/env python3
"""VENDOR-ATTR-R01 (task #31) controls. Covers: real library-id extraction (verified against the
real re2 vendored abseil-cpp finding from the overnight-diagnostic-100 run's own live output, not
a synthetic stand-in); PACKAGE_OWNED_HINT/UNKNOWN findings never attributed; unresolved findings
never attributed; cross-package deduplication on byte-identical vendored content; NO
deduplication across genuinely different content (a different vendored version, or an unrelated
file that happens to share a relpath); the two headline numbers (deduplicated_count vs
raw_exposure_count) reported separately, never collapsed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vendored_attribution as va

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def mk_finding(source_path, hint, resolved=True, content_hash="deadbeef", **extra):
    f = {"provenance": {"resolved": resolved, "provenance_hint": hint, "source_path": source_path,
                         "content_hash": content_hash if resolved else None}}
    f.update(extra)
    return f


# --- real re2 evidence, from the live overnight-diagnostic-100 run itself ---
OVERNIGHT_OUTPUT = ("/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2/npm_corpus/"
                     "overnight_100/overnight_diagnostic_working.jsonl")
re2_record = None
if os.path.isfile(OVERNIGHT_OUTPUT):
    for line in open(OVERNIGHT_OUTPUT):
        rec = json.loads(line)
        if rec.get("package_name") == "re2":
            re2_record = rec
            break

if re2_record is not None:
    va.attribute_record(re2_record)
    vendored = [f for f in re2_record.get("oob_write_candidates", [])
                if (f.get("provenance") or {}).get("provenance_hint") == "VENDORED_HINT"]
    ck("real re2 evidence: at least one real VENDORED_HINT oob_write_candidates finding exists",
       len(vendored) > 0)
    if vendored:
        f = vendored[0]
        sp = f["provenance"]["source_path"]
        att = f.get("vendored_attribution", {})
        ck(f"real re2 finding ({sp}): library_id correctly extracted as 'abseil-cpp'",
           att.get("vendored_library_id") == "abseil-cpp")
        ck("real re2 finding: attribution reads '<library> as bundled by <package>', not an "
           "unqualified package finding",
           att.get("attribution") == "abseil-cpp as bundled by re2")
        ck("real re2 finding: relpath_within_vendor_dir strips the vendor root, keeps the real "
           "path inside abseil-cpp",
           att.get("relpath_within_vendor_dir", "").startswith("absl/"))
    package_owned = [f for f in re2_record.get("oob_index_write_candidates", [])
                     if (f.get("provenance") or {}).get("provenance_hint") == "PACKAGE_OWNED_HINT"]
    if package_owned:
        ck("real re2 PACKAGE_OWNED_HINT finding: never attributed (no vendored_attribution key "
           "with status ATTRIBUTED)",
           (package_owned[0].get("vendored_attribution") or {}).get("status") != "ATTRIBUTED")
else:
    print("SKIP: overnight-diagnostic-100's re2 record not yet available in this run -- "
          "real-evidence checks skipped, synthetic checks below still run")

# --- library id extraction, unit level ---
lib, rest = va.extract_vendored_library_id("vendor/abseil-cpp/absl/base/internal/strerror.cc")
ck("unit: vendor/<lib>/... extracts lib='abseil-cpp', rest starts with absl/",
   lib == "abseil-cpp" and rest.startswith("absl/"))
lib2, rest2 = va.extract_vendored_library_id("deps/openssl/ssl/ssl_lib.c")
ck("unit: deps/<lib>/... extracts lib='openssl'", lib2 == "openssl" and rest2 == "ssl/ssl_lib.c")
lib3, rest3 = va.extract_vendored_library_id("src/main.c")
ck("unit: a package-owned path (no vendor marker) extracts (None, None)",
   lib3 is None and rest3 is None)

# --- PACKAGE_OWNED_HINT / UNKNOWN / unresolved never attributed ---
f_owned = mk_finding("src/main.c", "PACKAGE_OWNED_HINT")
va.attribute_finding(f_owned, "some-pkg")
ck("PACKAGE_OWNED_HINT finding: never attributed", "vendored_attribution" not in f_owned)

f_unknown = mk_finding(None, "UNKNOWN", resolved=False)
va.attribute_finding(f_unknown, "some-pkg")
ck("UNKNOWN/unresolved finding: never attributed", "vendored_attribution" not in f_unknown)

f_unresolved_vendored = mk_finding("vendor/zlib/inflate.c", "VENDORED_HINT", resolved=False)
va.attribute_finding(f_unresolved_vendored, "some-pkg")
ck("VENDORED_HINT but provenance.resolved=False: never attributed (no real path to attribute "
   "from at all)", "vendored_attribution" not in f_unresolved_vendored)

# --- cross-package deduplication: byte-identical vendored file, two different packages ---
pkg_a_finding = mk_finding("vendor/zlib/inflate.c", "VENDORED_HINT", content_hash="samehash123",
                           line=42, call="memcpy")
pkg_b_finding = mk_finding("third_party/zlib/inflate.c", "VENDORED_HINT", content_hash="samehash123",
                           line=42, call="memcpy")
rec_a = {"package_name": "pkg-a", "oob_write_candidates": [pkg_a_finding]}
rec_b = {"package_name": "pkg-b", "oob_write_candidates": [pkg_b_finding]}
agg = va.aggregate_vendored_dedup([rec_a, rec_b])
summary = va.summarize(agg)
ck("dedup: two DIFFERENT packages bundling byte-identical zlib/inflate.c (different vendor "
   "roots, same content_hash) collapse to ONE deduplicated entry",
   summary["oob_write_candidates"]["deduplicated_count"] == 1)
ck("dedup: raw_exposure_count correctly counts BOTH real occurrences (not collapsed away)",
   summary["oob_write_candidates"]["raw_exposure_count"] == 2)
the_bucket = next(iter(agg["oob_write_candidates"].values()))
ck("dedup: the deduplicated entry lists both real bundling packages",
   the_bucket["packages"] == ["pkg-a", "pkg-b"])

# --- NO dedup across genuinely different content (different vendored version) ---
pkg_c_finding = mk_finding("vendor/zlib/inflate.c", "VENDORED_HINT", content_hash="differenthash456",
                           line=42, call="memcpy")
rec_c = {"package_name": "pkg-c", "oob_write_candidates": [pkg_c_finding]}
agg2 = va.aggregate_vendored_dedup([rec_a, rec_c])
summary2 = va.summarize(agg2)
ck("no false dedup: same relpath, DIFFERENT content_hash (a different vendored version) -> "
   "TWO deduplicated entries, not incorrectly collapsed to one",
   summary2["oob_write_candidates"]["deduplicated_count"] == 2)

# --- distinct sites in the same file must not collapse on relpath+hash alone ---
pkg_a_finding2 = mk_finding("vendor/zlib/inflate.c", "VENDORED_HINT", content_hash="samehash123",
                            line=99, call="memmove")
rec_a2 = {"package_name": "pkg-a", "oob_write_candidates": [pkg_a_finding, pkg_a_finding2]}
agg3 = va.aggregate_vendored_dedup([rec_a2])
summary3 = va.summarize(agg3)
ck("two distinct real sites in the SAME vendored file (different line+call) stay TWO separate "
   "deduplicated entries",
   summary3["oob_write_candidates"]["deduplicated_count"] == 2)

print(f"VENDOR_ATTR_R01_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
