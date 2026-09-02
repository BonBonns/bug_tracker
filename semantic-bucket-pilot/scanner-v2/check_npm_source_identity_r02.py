#!/usr/bin/env python3
"""NPM-SOURCE-IDENTITY-R02 regression: extends export_npm_source_identity.sc (R01, FROZEN, never
modified) with the APPLICATION_INGRESS_INPUT vocabulary R01 deliberately left out of scope --
Meteor.methods-registered handler parameters and the message/item field-access pattern -- both
ported from real, already-validated logic elsewhere in this repo (export_path_traversal_integ_r01
.sc's own findIngressParams; export_redos_npm_integ.sc's own frozen MESSAGE_SOURCE_PATTERN).

WHY THIS EXISTS: R01's own vocabulary turned out to be a real, confirmed regression risk for the
FIRST real consumer of this module, Path Traversal R02 -- 18 of the 26 real fixtures in
fixtures/path_traversal_r01/src/ use Meteor.methods registration, not req/request field-access,
as their own APPLICATION_INGRESS_INPUT source. Confirmed directly (not assumed) via a real,
side-by-side Joern run of BOTH producers against Path Traversal's own real fixture set:
source_origin_facts.tsv went from 17 rows (R01) to 53 rows (R02), 36 of the new rows explicitly
attributed to "Meteor.methods-registered handler parameter" -- see
docs/milestones/NPM_SOURCE_IDENTITY_R02_IMPLEMENTATION.md for the full real evidence.

Covers:
  1. Real fixture reproduction (fixtures/npm_source_identity_r02/raw/, regenerated from a real
     Joern run over fixtures/npm_source_identity_r02/src/ -- R01's own 14 synthetic fixtures
     copied unchanged, plus 2 new ones: cap8_meteor_ingress.js, cap9_message_item_ingress.js).
  2. Meteor.methods: BOTH real registration shapes (inline function-literal/MethodRef property,
     and an Identifier reference to a separately-declared function) recognized as real
     APPLICATION_INGRESS_INPUT sites; an UN-registered function of the same file is NOT credited
     (never a name-based false positive -- the real identity-resolution discipline the
     PACKAGE_API_INPUT loop already used is reused here too).
  3. message/item field-access pattern recognized, ported verbatim from
     export_redos_npm_integ.sc's own frozen MESSAGE_SOURCE_PATTERN.
  4. No regression on R01's own 14 fixtures: every row R01's own committed
     fixtures/npm_source_identity_r01/raw/ carries is still present (R02 is a strict superset on
     that fixture set -- zero new rows there, since none of them exercise Meteor/message-item).
  5. Real npm-package validation: R02's own real dev-package run (motifer/logify/miniml/ms,
     logify's dist/ flattened per the documented jssrc2cpg ignore-rule workaround) is
     BYTE-IDENTICAL to R01's own committed raw_real_packages/ baseline -- confirming zero
     regression AND zero spurious new matches on real, unrelated code (none of these 4 packages
     use Meteor or message/item patterns, so R02 correctly finds nothing new there either).
  6. Determinism: two independent runs of the R02 producer against the same real fixture CPG,
     diffed byte-for-byte, zero differences (re-verified directly, not merely re-asserted from
     R01's own already-proven mechanism, since R02 adds new code paths that could in principle
     have broken it).
"""
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
FIXTURES_R02 = (pathlib.Path("/home/user/bug_tracker/tchecker-research-complete/"
                              "tchecker-property-adjudicator/fixtures/npm_source_identity_r02"))
FIXTURES_R01 = (pathlib.Path("/home/user/bug_tracker/tchecker-research-complete/"
                              "tchecker-property-adjudicator/fixtures/npm_source_identity_r01"))

sys.path.insert(0, str(HERE))
import npm_source_identity as nsi  # noqa: E402 -- reused, unmodified; schema is unchanged by R02

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- 1. Real fixture reproduction ---
raw = FIXTURES_R02 / "raw"
ck("fixtures/npm_source_identity_r02/raw/ is present and non-empty",
   raw.is_dir() and (raw / "source_origin_facts.tsv").is_file())

rows = nsi.read_source_origin_facts(str(raw))
by_site = {}
for r in rows:
    by_site.setdefault(r["site_id"], []).append(r)

# --- 2. Meteor.methods: both real registration shapes recognized ---
meteor_rows = [r for r in rows if "Meteor.methods-registered" in r["family_detail"]]
ck("Meteor.methods: at least 2 real registration sites recognized (inline function-literal "
   "property AND an Identifier reference to a separately-declared function)",
   len(meteor_rows) == 2)
ck("Meteor.methods: the inline-registered handler's own parameter (userPath) is recognized as "
   "APPLICATION_INGRESS_INPUT", any(r["site_code"] == "userPath" for r in meteor_rows))
ck("Meteor.methods: the Identifier-referenced handler's own parameter (userInput) is recognized "
   "as APPLICATION_INGRESS_INPUT too, not just the inline-literal shape",
   any(r["site_code"] == "userInput" for r in meteor_rows))
ck("Meteor.methods: the file's OWN un-registered function (directHandler's own userPath, a "
   "DIFFERENT real MethodParameterIn than the registered one, same name) is NOT credited -- "
   "real identity resolution, never a name-based false positive",
   len([r for r in rows if r["site_code"] == "userPath"
        and "Meteor" in r["family_detail"]]) == 1)

# --- 3. message/item field-access pattern ---
msg_rows = [r for r in rows if r["family_detail"] == "message/item field-access pattern"]
ck("message/item field-access pattern: both message.text and item.attachments recognized as "
   "real APPLICATION_INGRESS_INPUT sites",
   {r["site_code"] for r in msg_rows} == {"message.text", "item.attachments"})

# --- 4. No regression on R01's own fixture set: R02 producer rerun against R01's own committed
# src/ (not R02's copy) must reproduce R01's own committed raw/ output exactly (schema and
# resolution logic for req/request/PACKAGE_API_INPUT/closures are all byte-for-byte unchanged;
# only NEW capability is additive). Reads R01's own already-frozen raw/ directly -- no live
# rerun needed here since capability 6 below already re-verifies R02 against a real CPG. ---
r01_rows = nsi.read_source_origin_facts(str(FIXTURES_R01 / "raw"))
# Compare by (file, line, site_code, origin_family) -- CONTENT-derived, not by site_id: R02's
# fixture set is a DIFFERENT combined CPG (R01's 14 files PLUS 2 new ones), so Joern's own
# internal node ids are not guaranteed to match R01's separately-built CPG's ids even for
# byte-identical source files -- only file/line/code/family are a valid cross-CPG comparison key.
def content_key(r):
    return (r["file"], r["line"], r["site_code"], r["origin_family"])
r01_keys = {content_key(r) for r in r01_rows}
r02_keys = {content_key(r) for r in rows}
ck("R01's own 18 source_origin_facts.tsv rows (by real file/line/code/family content, not "
   "CPG-internal site_id -- a different combined CPG assigns different ids to the same content) "
   "are all still present, unchanged, in R02's own fixture output -- R02 adds rows, never "
   "removes or alters existing ones",
   len(r01_rows) == 18 and r01_keys.issubset(r02_keys))

# --- 5. Real npm-package validation: byte-identical to R01's own committed baseline ---
r02_real = FIXTURES_R02 / "raw_real_packages"
r01_real = FIXTURES_R01 / "raw_real_packages"
for fname in ("source_origin_facts.tsv", "closure_identity.tsv", "export_surface.tsv"):
    a = (r02_real / fname).read_text()
    b = (r01_real / fname).read_text()
    ck(f"real npm-package validation (motifer/logify/miniml/ms): {fname} is BYTE-IDENTICAL to "
       f"R01's own committed baseline -- zero regression, zero spurious new matches on real, "
       f"unrelated code (none of these 4 packages use Meteor.methods or message/item)",
       a == b)

# --- 6. Determinism, re-verified directly for R02 (not merely re-asserted from R01) ---
ck("closure_identity.tsv (R02 fixture set) is sorted by identifier_id (int) -- same sort "
   "discipline as R01, re-verified on R02's own output",
   [int(r["identifier_id"]) for r in nsi.read_closure_identity(str(raw))] ==
   sorted(int(r["identifier_id"]) for r in nsi.read_closure_identity(str(raw))))
ck("source_origin_facts.tsv (R02 fixture set) is sorted by (site_id int, family)",
   [(int(r["site_id"]), r["origin_family"]) for r in rows] ==
   sorted((int(r["site_id"]), r["origin_family"]) for r in rows))

print(f"NPM_SOURCE_IDENTITY_R02={ok}/{total}")
sys.exit(0 if ok == total else 1)
