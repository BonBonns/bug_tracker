#!/usr/bin/env python3
"""NPM-CORPUS item 6/7: the full frozen pipeline for ONE package, orchestrating every stage
validated manually against a real package (@fqlan/add-example-prebuild) before this script
was written: download -> extract -> c2cpg -> export_c_cpp_facts_v03.sc ->
normalize_c_cpp_facts_v03.py -> jssrc2cpg -> export_neutral.sc -> normalize_joern_facts.py ->
polyglot_compat_adapter.py -> link_napi_facts.py -> resource_guard_verdict_r04.py (using this
package's own real, previously-extracted build_configuration.tsv evidence).

Every stage records real wall-clock time and a best-effort peak-RSS delta (via
`resource.getrusage(RUSAGE_CHILDREN).ru_maxrss`, checked immediately before and after each
subprocess -- an honest, disclosed limitation: this is a running maximum across all children
reaped so far, not a hardware-isolated per-process measurement, since no `/usr/bin/time` is
installed in this environment; still real, not fabricated).

Every package ends with exactly one primary status from the required taxonomy: ANALYZED,
DOWNLOAD_FAILED, EXTRACTION_FAILED, JS_CPG_FAILED, CPP_CPG_FAILED, EXPORT_FAILED,
NORMALIZATION_FAILED, BINDING_UNRESOLVED, RESOURCE_LIMIT. (NO_JS_TS_SOURCE, NO_CPP_SOURCE,
NO_PACKAGE_OWNED_NATIVE_BINDING, DOWNLOAD_FAILED, INTEGRITY_FAILED were already assigned by
eligibility_filter.py for the non-eligible majority -- this script only runs for packages
already marked ANALYZED there.) All intermediate artifacts (tarball, extracted tree, CPG
binaries) are deleted after each package completes, regardless of outcome, so disk usage
stays bounded across the corpus.

R06 CHANGE (this file only -- `run_pipeline_one.py` itself, hash `1c031795a3383ff63aa1a22e
382daeae`, stays frozen and untouched; this is a new, separate, byte-for-byte-copy-plus-fix
file, same lineage discipline as every prior R0N revision in this project): before deleting
work_root, write a minimal compressed per-package evidence bundle via
`evidence_bundle.write_evidence_bundle()` -- see that module's own docstring for exactly what
is and is not preserved and why. This is the fix for the real, disclosed gap found auditing
this pipeline: the frozen version bounds disk usage by deleting EVERYTHING, which also
silently deletes the only path to a verdict-only rerun (no saved raw facts for R04/R05/R06
to re-scan without a full Joern rebuild). CPG binaries and the extracted source tree are
still deleted -- only real scanner-consumed evidence is kept, compressed, per package.

REDOS INTEGRATION (roadmap step 8, first of 4 JS/TS classes): after the Nan stage, this file also
runs ReDoS (frozen, merged: export_redos_npm_integ_r02.sc + redos_verdict.py) as part of this same
per-package chain, reusing the js_bin CPG and pkg_dir this function already builds/extracts above
rather than the standalone study/redos_npm/pilot25/run_pilot25_r02.py's own from-scratch
download+build.

JS FRONTEND ENTRYPOINT-COVERAGE CORRECTION (shared, applies to js_bin itself): ported from
study/redos_npm/pilot25/run_pilot25_r02.py's own real run_one() algorithm (entrypoint-coverage
correction via frontend_coverage_check.py, imported and never modified) -- but, unlike its
original ReDoS-only placement, now applied directly to js_bin right after the initial jssrc2cpg
build, BEFORE js_export/js_facts.json or any downstream stage runs, so every stage that reuses
js_bin (js_facts.json, Nan capability detection, ReDoS, Path Traversal, Serialize DoS -- all of
them) gets the correction, not only ReDoS. This was a real, confirmed gap: jssrc2cpg's own
default ignore rules (a folder-name list including "dist", a .d.ts-style filename-suffix regex,
an unanchored node_modules substring match) silently drop a package.json-resolved entrypoint
before a single CPG node for it exists -- and shipping compiled dist/ output as the real runtime
code is the standard convention for a published TypeScript library, not an edge case. Confirmed
severe on two real packages: multi-spec-parser (uncorrected CPG: 3 ReDoS sink targets, 0
dangerous; corrected: 50 sink targets, 1 REAL dangerous candidate the uncorrected scan never
saw) and node-llama-cpp (uncorrected js_bin: 0 functions/0 calls parsed from 560 real on-disk
JS/TS files; corrected: 280 files/4573 methods/91378 calls). See the inline comments at the
correction block below for the one real structural difference from frontend_coverage_check.py's
own check_package(): pass 1 is never rebuilt, since js_bin already IS it.
"""
import hashlib
import importlib
import json
import os
import resource
import shutil
import subprocess
import sys
import tarfile

from evidence_bundle import write_evidence_bundle
from extract_build_config import classify_target_aware
import time
import urllib.error
import urllib.request

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
CPP_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend"
JS_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/javascript-typescript/joern"
POLYGLOT = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/polyglot/link_napi_facts.py"
SCANNER_V2 = "/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2"

# Module-level import, not a local `import X` inside run_one() -- a local import of a name that
# some earlier-defined nested closure in this same function also references makes that name a
# function-local cell for the WHOLE enclosing function body (Python resolves locals statically,
# not by execution order), which breaks the closure's own reference to what it expected to be a
# global. Confirmed as a real bug this way for `importlib` (run_gates_class()'s own closure) when
# these three were first wired in as local imports; fixed by moving all three here instead.
sys.path.insert(0, SCANNER_V2)
import provenance                       # noqa: E402 -- task #35, LOCK_BALANCE/PROTECTED_FIELD/OOB integration
import reachability_tier                # noqa: E402 -- task #32, same integration
import staged_enablement                # noqa: E402 -- tasks #36-40, same integration

# REDOS INTEGRATION (roadmap step 8): the frozen R02 producer + reducer, reused verbatim from
# study/redos_npm/pilot25/run_pilot25_r02.py's own already-validated paths, never modified here.
R02_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/"
                "producers/export_redos_npm_integ_r02.sc")
REDOS_VERDICT = os.path.join(SCANNER_V2, "redos_verdict.py")
# JS FRONTEND ENTRYPOINT-COVERAGE CORRECTION: frontend_coverage_check.py's own audit dir --
# this used to be ReDoS-only (hence the name), now used earlier and shared by every JS/TS
# stage (see the module docstring and the correction block right after the jssrc2cpg build).
REDOS_FCC_AUDIT_DIR = os.path.join(SCANNER_V2, "study", "redos_npm", "pilot25", "audit")

# PATH TRAVERSAL INTEGRATION (roadmap step 8, second of 4 JS/TS classes): the frozen, merged
# shared npm-source-identity producer (its own latest revision, R02 -- restores Meteor.methods/
# message-item ingress recognition, see NPM_SOURCE_IDENTITY_R02_IMPLEMENTATION.md) MUST run
# against the SAME js_bin BEFORE Path Traversal's own R02 producer, writing source_origin_facts.tsv
# into the SAME rawDir Path Traversal's own producer reads from -- both required upstream steps,
# never invoked by Path Traversal's own producer itself (see that file's own header comment for
# the full disclosure of this dependency). All three files (frozen; never modified here).
NPM_SOURCE_IDENTITY_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                                 "tchecker-property-adjudicator/producers/"
                                 "export_npm_source_identity_r02.sc")
PATH_TRAVERSAL_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                            "tchecker-property-adjudicator/producers/"
                            "export_path_traversal_integ_r02.sc")
PATH_TRAVERSAL_VERDICT = os.path.join(SCANNER_V2, "path_traversal_verdict.py")

# SERIALIZE DOS INTEGRATION (roadmap step 8, third of 4 JS/TS classes): Serialize DoS was built
# by a separate, parallel session and merged into develop as-is under its own directory
# (tchecker-research-complete/serialize-dos-r01/), NOT the standard producers/ layout -- some of
# its own producers ARE in that standard location because they are pre-existing/frozen
# (export_serialize_facts.sc below), but its own newest producer (transform_presence.sc) and its
# reducer (serialize_dos_r03.py) live under serialize-dos-r01/. Its own module docstring says
# "reportable is fixed to false on every finding: pipeline integration is explicitly deferred" --
# this is exactly that deferred integration. All five files below are frozen; never modified here.
SERIALIZE_DOS_R01_DIR = "/home/user/bug_tracker/tchecker-research-complete/serialize-dos-r01"
SERIALIZE_FACTS_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                             "tchecker-property-adjudicator/producers/export_serialize_facts.sc")
TRANSFORM_PRESENCE_PRODUCER = os.path.join(SERIALIZE_DOS_R01_DIR, "producers", "transform_presence.sc")
SETUP_CANDIDATE_MULTISOURCE_PRODUCER = os.path.join(
    SERIALIZE_DOS_R01_DIR, "producers", "setup_candidate_multisource.sc")
PROPERTY_PROPAGATION_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                                  "tchecker-property-adjudicator/producers/"
                                  "export_property_propagation.sc")
ADJUDICATOR_DIR = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/adjudicator")
SERIALIZE_DOS_PROPERTY_CONFIG = ("/home/user/bug_tracker/tchecker-research-complete/"
                                  "tchecker-property-adjudicator/property_configs/serialize_dos.json")
# NO_HINTS is no longer referenced directly here: ADJUDICATE-ITERATIVE-R01's
# adjudicate_iterative.run_adjudicate_sink_iterative() (the Serialize DoS stage's own call
# below) starts every invocation with its own real, empty {} accumulated-hints file (same
# content as adjudicator/no_hints.json) and only ever adds a REAL answer to it via ask_fn --
# unset here (ask_fn=None), so this stage never becomes non-empty either. This constant used to
# be needed to avoid a real, confirmed bug: without SOME real TCH_HINTS file, adjudicate_js.py
# falls back to ITS OWN hardcoded fixture-only canned hints (keyed
# "xf0.<property_id_suffix>"/"xf1.<property_id_suffix>", meant only for its own dev-time
# fixtures) instead of cleanly stopping for real review -- see adjudicate_iterative.py's own
# module docstring for the fuller, now-generalized story (every sink is asked about via a real
# loop, not a single invocation, and any alternative genuinely left unaddressed is disclosed
# rather than silent).
# srcPattern="req.body": the same real, already-validated value every fixture and the real
# motifer@26.1.1 validation in the whole R01-R03 lineage uses (setup_candidate_multisource.sc's
# own module docstring / check_setup_candidate_multisource.py's M7 control).
SERIALIZE_DOS_SRC_PATTERN = "req.body"

# LLM-INPUT INTEGRATION (roadmap step 8 successor -- discovered mid-session, not one of the
# originally-tracked 4 JS/TS classes: an already-built, already-gated (gate_llm_input.py, 7/7)
# OWASP LLM Top-10 property -- LLM02 insecure output handling (model output reaching an
# eval/exec/SQL/HTML/redirect sink) and LLM01 prompt injection (request data reaching the
# system-role instruction position) -- that was never wired into any pipeline at all. Real-
# world-validated already (docs/LLM_INPUT_REALWORLD_PLUGIN_SCAN.md, a genuine RocketChat
# plugin scan that found and fixed two real producer bugs). export_llm_facts.sc's own
# signature (cpgFile, outDir) and llm_input_verdict.py's own derive(raw) -- taking only the
# raw facts dir, no src_dir, no property_config, no semantic-review/adjudicator step at all --
# are both frozen and reused verbatim, never modified.
LLM_FACTS_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                       "tchecker-property-adjudicator/producers/export_llm_facts.sc")

# NOSQLI INTEGRATION (roadmap step 8 successor, discovered alongside LLM-input: another
# already-built, never-wired class -- ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE, grounded in
# RocketChat's own repeated, disclosed history -- CVE-2021-22911, HackerOne #3564655/
# CVE-2026-29198, GHSA-hgq6-9jg2-wf3f/CVE-2026-30833 -- see NOSQLI_SINK_SEMANTICS_MATRIX.md/
# NOSQLI_STAGE2_PROPERTY_EFFECTS.md/NOSQLI_SCANNER_FIXES.md/NOSQLI_STAGE3_RESULT_AND_AJV_GAP.md).
# Stage 1 (sink semantics, 10/10) + Stage 2 (property effects, 9/9) + Stage 3 (AJV route-schema-
# gate detection, 4/4 + the header/AJV false-lead fixes) were all already frozen and fixture-
# verified in export_nosqli_integ.sc before this pipeline existed -- what was genuinely missing
# was any reducer at all (unlike ReDoS/Path Traversal/Serialize DoS, which already had one) and
# any pipeline wiring. export_nosqli_integ.sc's own signature is (cpgFile, rawDir, srcLabel,
# skipCount) -- same rawDir/srcLabel convention as ReDoS/Path Traversal, not LLM-input's
# cpgFile/outDir. NOSQLI-INTEG-R01-FIX01 (this session): the producer already computed each query
# call's own field identity (fieldKind/fieldName/value-operand code) per target, but only ever
# printed it to stderr -- source_facts.tsv itself carried 7 permanently-blank reserved columns and
# never persisted it, so two DISTINCT fields at the SAME call (`findOne({email, statusFlag})`)
# were indistinguishable to any reducer reading that file back. Confirmed structurally (not
# hypothetical) via a constructed two-distinct-field fixture. Fixed by writing field identity into
# three of those reserved columns (5/6/7); adjudicate_js.py itself only ever reads columns 0-4, so
# this is additive, and a same-fixture regression run before/after the fix produced byte-identical
# row counts, confirming nothing else changed. nosqli_verdict.py (new, matching redos_verdict.py's/
# path_traversal_verdict.py's own <raw_dir> <src_dir> <out.json> CLI contract) is the new reducer;
# the producer itself received only the FIX01 column addition above, nothing else.
NOSQLI_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/producers/export_nosqli_integ.sc")
NOSQLI_VERDICT = os.path.join(SCANNER_V2, "nosqli_verdict.py")

# SSRF INTEGRATION (roadmap step 8 successor, discovered alongside LLM-input/NoSQLi: the third
# already-built, never-wired class -- ATTACKER_CONTROL_OF_REQUEST_HOST, see
# tchecker-property-adjudicator/docs/milestones/JS_SSRF_SOURCE_R01_WEBEXT_BRIDGE.md and siblings).
# Stage 1 (sink semantics) + Stage 2 (property effects) were already frozen and integrated into
# export_ssrf_integ.sc before this session -- that producer ALSO already computes real
# BROKEN/OPEN/ESTABLISHED per-alternative containment tiering itself (unlike NoSQLi's producer,
# which only ever emits already-guard-filtered rows), the same shape Path Traversal's own producer
# uses -- so ssrf_verdict.py (new) follows path_traversal_verdict.py's own template, not
# nosqli_verdict.py's. What was genuinely missing here, same as NoSQLi: any Python reducer at all,
# and any pipeline wiring.
#
# export_ssrf_integ.sc's own signature is (cpgFile, rawDir, srcLabel, browserSourceTsv = "") --
# the same rawDir/srcLabel convention as ReDoS/Path Traversal/NoSQLi, plus one OPTIONAL parameter
# (browserSourceTsv) that bridges a separate, frozen WebExtension-tab/external-message source
# class (JS-SSRF-SOURCE-R01/R02, gated 16/16 + 10/10) into the source pool. That bridge is
# browser-extension-specific (tabs.onCreated/onUpdated, runtime.onMessageExternal) -- structurally
# irrelevant to a generic npm-library corpus, so this wiring deliberately never passes it (default
# ""), matching how the corpus scan never builds a browser-extension host environment for any
# other property either. The source model actually exercised here is the SAME
# req.*/message.*/Meteor.methods application-ingress boundary every other property in this
# pipeline already uses (SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|
# url)(\\..*)?") -- there is no separate npm-package-own-exported-function-parameter source
# family for this property at all (unlike ReDoS's PACKAGE_API_INPUT_REACHABLE), so on a generic
# npm library (no Express/Meteor-shaped request handling of its own) this stage will very likely
# find zero source candidates, same real-world caveat NoSQLi's own req.*-based source model has.
#
# SSRF-INTEG-R01-FIX01 (this session, in export_ssrf_integ.sc): `note` -- WHY a given (sink,
# origin) alternative was classified BROKEN/OPEN ("host overwritten by literal assignment: ...",
# "guard-dominance candidate: ...", "unrecognized call: ...") -- was already computed per row but
# only ever printed to the producer's own stderr; property_outcome.tsv's own trailing two columns
# were always the literal placeholder "-1","-1". Confirmed adjudicate_js.py only ever reads
# columns 0/1/2 of this file, so it was fixed to write `note` into column 3 (column 4 stays "-1",
# row width unchanged at 5 columns). A same-fixture regression run before/after the fix produced
# byte-identical row counts; all four of this producer's own pre-existing WebExtension regression
# gates (PORTABLE_SSRF_BRIDGE_CONTROLS, WEBEXT_SSRF_BRIDGE, WEBEXT_EXTERNAL_SSRF_BRIDGE,
# WEBEXT_SSRF_LLM_HANDOFF) still pass unchanged after this fix.
SSRF_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                  "tchecker-property-adjudicator/producers/export_ssrf_integ.sc")
SSRF_VERDICT = os.path.join(SCANNER_V2, "ssrf_verdict.py")

# FIVE MORE CLASSES (found via ANALYZER_CLASS_INVENTORY.md's own repository-wide audit, section
# 3.5 -- real, gated, self-contained JS/TS npm-applicable properties that predate this session,
# living under tchecker-research-complete/gates/, never wired into any pipeline): Guard
# Fallthrough, Global Singleton Mutation, Denylist Pattern Bypass, Validation Bypass (loop-
# control divergence), Malicious NPM Install Exfiltration. Each already has its own frozen
# verdict.py (derive()-style reducer, same "predates the reportable convention" shape as
# llm_input_verdict.py -- reportable is set here, orchestration-only, never inside the frozen
# reducer) and its own gate script (re-verified fresh this session, not trusted from old
# self-reported numbers: GUARD_FALLTHROUGH=6/6, DENYLIST_BYPASS=6/6, GLOBALMUT=6/6,
# VALIDATION_BYPASS=6/6, MALICIOUS_NPM=13/13 -- all reproduced from the bundled fixtures'
# checked-in cpg.bin via the real producers, not just re-run against static TSVs, and every
# rebuilt raw/ dir diffed byte-identical against the bundled one, except two tables
# (loop_collections.tsv/loop_exits.tsv/loop_sink_sites.tsv/loopctl.tsv appearing in the denylist
# fixture, loopctl.tsv appearing in the loop fixture) that neither verdict.py actually reads --
# confirmed extraneous, not a real producer gap).
#
# Producer convention: `exec(cpgFile: String, outDir: String)` -- same as export_llm_facts.sc,
# not the rawDir/srcLabel convention of ReDoS/Path Traversal/NoSQLi/SSRF. Two of the five
# (Guard Fallthrough, Global Singleton Mutation) ALSO require module_export_identity.sc
# (a shared, portable-engine-full-review-package producer writing require_bindings.tsv/
# module_exports.tsv/import_calls.tsv/etc.) to run first, into the SAME outDir -- confirmed by
# rebuild, not assumed from scan_pkg.sh's own reference list (which predates this session and
# was found, via that same rebuild, to still be complete and correct for these two). Denylist
# Bypass, Validation Bypass, and Malicious NPM Install Exfil need no such prerequisite.
#
# Every one of these five verdict.py's own `derive()` returns findings for BOTH the CANDIDATE_*
# shape AND every SAFE_* control it evaluated (unlike every other property in this pipeline,
# whose own reducer already filters down to only the reportable-worthy shape) -- so, unlike
# every prior wiring in this pipeline, record["..._findings"] here is explicitly filtered to
# verdict.startswith("CANDIDATE") before reportable=False is attached; the full, unfiltered
# derive() output (SAFE_* rows included) is still bundled verbatim in each stage's own
# "*_out.json" file, so nothing is silently lost, only kept out of the aggregator-facing key.
MODULE_EXPORT_IDENTITY_PRODUCER = ("/home/user/bug_tracker/tchecker-research-complete/"
                                    "portable-engine-full-review-package/frontends/"
                                    "javascript-typescript/joern-ts/module_export_identity.sc")
GATES_DIR = "/home/user/bug_tracker/tchecker-research-complete/gates"
GUARD_FALLTHROUGH_PRODUCER = os.path.join(
    "/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/producers",
    "export_guard_facts.sc")
GLOBALMUT_PRODUCER = os.path.join(
    "/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/producers",
    "export_globalmut_facts.sc")
DENYLIST_BYPASS_PRODUCER = os.path.join(
    "/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/producers",
    "export_denylist_facts.sc")
VALIDATION_BYPASS_PRODUCER = os.path.join(
    "/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/producers",
    "export_loop_facts.sc")
MALICIOUS_NPM_PRODUCER = os.path.join(
    "/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator/producers",
    "export_mal_facts.sc")
# Each of the five verdict.py files themselves live under GATES_DIR and are imported by module
# name (not by path) in run_gates_class() below -- GATES_DIR is added to sys.path once, right
# before that helper is defined, matching ADJUDICATOR_DIR's own role for llm_input_verdict.py.

# ESCAPE-PARITY-BOUNDARY INTEGRATION: a quote-boundary parser rule that cannot establish
# escape-run parity (a single fixed-position lookbehind, e.g. `s[i-1] != '\\'`, cannot
# distinguish an escaped quote `\"` from an escaped backslash followed by a real quote `\\"`).
# Built and gated standalone across nine revisions (R01-R09, 95/95 controls across 8 gate
# scripts -- see tchecker-research-complete/escape-parity-boundary-r01/FREEZE_LINEAGE.md and
# SAME_BOUNDARY_SCOPE_R09.md for the property's own lineage), never wired into any pipeline
# until now. Like LLM-input, and unlike ReDoS/Path Traversal/NoSQLi/SSRF, there is no
# adjudicator/semantic-review step for this property: every classification the frozen reducer
# emits (SINGLE_POSITION_INDEX_CHECK candidate / PARITY_ESTABLISHED_IN_METHOD negative /
# UNRESOLVED_DELIMITER_IDENTITY abstention at the parser layer, and REACHABLE /
# NOT_ESTABLISHED at the reachability-chain layer) is already fully decided by real CPG
# structure and real dataflow -- there is no genuinely open case here for an LLM to adjudicate,
# unlike SSRF's "is this on-path guard actually dominant" question. (Considered and rejected
# deliberately, not an oversight -- see the session's own discussion before this wiring: an
# LLM re-deriving an already-structurally-proven fact adds no correctness, only a place for
# occasional disagreement with a fact that was never actually open.)
#
# The JS/TS producer (producers/escape_parity_facts.sc) is a SINGLE script -- unlike the C/C++
# side's two-script split (parser facts + reachability facts separately) -- that emits BOTH
# the parser-layer facts (regex_sites/parser_quote_sites/parser_index_checks/
# parity_mechanisms) and the reachability facts (delayed_sources/transform_calls/consumers/
# chain_edges/execution_timing) in one pass against js_bin, using the SAME cpgFile/rawDir
# producer convention as ReDoS/Path Traversal/NoSQLi/SSRF (not LLM-input's cpgFile/outDir).
# escape_parity_chain.derive(raw_dir, "JAVASCRIPT") (frozen, reused verbatim, never modified)
# is the complete reducer for this property on JS/TS -- it already calls
# escape_parity_sites.derive() internally and layers the reachability chain on top, so this is
# one producer run + one derive() call, following LLM-input's own "import and call derive()
# directly" no-adjudicator discipline, not path_traversal_verdict.py's/ssrf_verdict.py's own
# adjudicate_iterative-driven template.
ESCAPE_PARITY_DIR = "/home/user/bug_tracker/tchecker-research-complete/escape-parity-boundary-r01"
ESCAPE_PARITY_PRODUCER = os.path.join(ESCAPE_PARITY_DIR, "producers", "escape_parity_facts.sc")

# LOCK_BALANCE / PROTECTED_FIELD / OOB_WRITE / OOB_INDEX_WRITE / OOB_READ / OOB_COMPARE
# INTEGRATION (tasks #36-40, STAGED-ENABLE-R01): six real, gated, npm-corpus-validated C/C++
# properties -- task #28's own integration-verification pilot
# (study/integration_verification_pilot/PILOT_CONCLUSION_AND_FOLLOWUPS.md) already reproduced
# real historical positives fresh through c2cpg (wolfSSL's own real CVE-2026-5264 recovery for
# LOCK_BALANCE/PROTECTED_FIELD), root-caused and fixed two real defects along the way (a
# capacity-derivation sentinel-collision bug in OOB_READ; a missing NAN registration idiom that
# would have wrongly bucketed every NAN-based native function as unreachable), and a real
# 100-package diagnostic run (`run_diagnostic_100.py`, a separate, one-off script, never this
# file) produced 3911 real raw findings, `reportable=False` verified on all of them by design.
# Every piece of supporting machinery this integration needs -- `provenance.py`'s fail-closed
# reportable formula (task #35), `reachability_tier.py`'s tiered JS-reachability classifier
# (task #32), `staged_enablement.py`'s per-property enablement gate (tasks #36-40) -- already
# exists, is gated, and is already merged into develop (confirmed directly by running every one
# of those gates fresh before writing any of this, not assumed from documentation). What was
# missing, confirmed by direct grep before writing this: none of it was ever invoked from this
# file's own real per-package flow -- only from the separate diagnostic script.
#
# Same cpp_raw/cpp_facts this file already builds for R04/R05/R06/Nan -- no new fact-generation
# work, matching the pilot's own central finding for this whole property family. LOCK_BALANCE/
# PROTECTED_FIELD run as a CLI subprocess (raw TSV dir in, JSON out -- same convention as R04/
# R05/R06's own scan stages); the four OOB producers run in-process via their own real
# `emit_candidates(cpp_facts_path)` function (avoids four extra subprocess spawns per package,
# matching `run_diagnostic_100.py`'s own `run_scanner_json()` precedent exactly).
#
# OOB_COMPARE's own producer still runs here, matching `run_diagnostic_100.py`'s own precedent
# and `evidence_bundle.py`'s own existing REQUIRED `oob_compare_out.json` entry -- it is
# deliberately, permanently excluded from `staged_enablement.ENABLED_PROPERTIES` (task #33's own
# real 33-package corpus survey found the detector sound but the bug shape genuinely rare in
# this corpus, not a wiring gap), so `enforce_staged_enablement()` below always forces its own
# findings non-reportable (`STAGE_NOT_ENABLED`) regardless of what this producer finds.
LOCK_BALANCE_VERDICT = os.path.join(SCANNER_V2, "lock_balance_verdict.py")
PROTECTED_FIELD_VERDICT = os.path.join(SCANNER_V2, "protected_field_verdict.py")
OOB_TOOLS_DIR = ("/home/user/bug_tracker/tchecker-research-complete/"
                  "portable-engine-full-review-package/tools")

JS_TS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
CPP_EXTS = (".c", ".cc", ".cpp", ".cxx")

# Real limits established from the 50-package pilot (see RESOURCE_LIMITS section of
# CORPUS_STATUS.md / the pilot commit message): 48/50 packages completed every stage in
# well under these standard timeouts (c2cpg max observed 41.4s, cpp_export max 31.7s,
# cpp_normalize median 0.24s). The 2/50 exceptions (re2, pqclean) are large, real, bundled
# C++ codebases (re2: 551 files, 1.34M raw fact rows) -- normalize alone took a real,
# reproduced 127.6s for re2, confirmed by manual re-run with a generous timeout, not a hang.
# TIMEOUT_MULTIPLIER lets the SAME script serve both the standard pass (multiplier=1) and the
# high-resource retry queue (multiplier=8 -> 1440s/720s ceilings) without duplicating logic.
TIMEOUT_MULTIPLIER = float(os.environ.get("NPM_CORPUS_TIMEOUT_MULTIPLIER", "1"))
STAGE_TIMEOUT = int(180 * TIMEOUT_MULTIPLIER)     # c2cpg / jssrc2cpg / cpp_export / js_export
NORMALIZE_TIMEOUT = int(180 * TIMEOUT_MULTIPLIER)  # cpp_normalize / js_normalize (re2's real 127.6s + margin)
LINK_TIMEOUT = int(90 * TIMEOUT_MULTIPLIER)        # polyglot_link
SCAN_TIMEOUT = int(90 * TIMEOUT_MULTIPLIER)        # r04_scan (reads raw TSVs directly, not the large normalized JSON)
# Path Traversal's own R02 producer (export_path_traversal_integ_r02.sc, the second of its two
# producers) does real per-source-to-sink dataflow/closure-identity resolution -- STAGE_TIMEOUT
# (180s) was calibrated before the JS_FRONTEND_COVERAGE fix existed, when this producer only ever
# saw a near-empty, uncorrected CPG and so never took long regardless of a real package's actual
# size. Once js_bin correctly reflects a package's real content (see js_frontend_coverage above),
# this producer's own real cost scales with it: reproduced directly on multi-spec-parser's real,
# corrected CPG (420 real source_origin_facts rows, 17 real sinks) -- 218s, confirmed by manual
# re-run with a generous timeout, not a hang (same "real, reproduced, not a hang" discipline
# NORMALIZE_TIMEOUT's own re2 case above already established for this file).
PATH_TRAVERSAL_PRODUCER_TIMEOUT = int(600 * TIMEOUT_MULTIPLIER)


def rss_now():
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss  # KB, running max


def run_stage(cmd, log_path, timeout=STAGE_TIMEOUT):
    before = rss_now()
    t0 = time.time()
    try:
        with open(log_path, "w") as log:
            proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        elapsed = time.time() - t0
        after = rss_now()
        return proc.returncode, elapsed, max(0, after - before), None
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        return None, elapsed, 0, "TIMEOUT"
    except Exception as e:
        elapsed = time.time() - t0
        return None, elapsed, 0, f"{type(e).__name__}: {e}"


def fetch_bytes(url, timeout=60, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "resource-guard-corpus-mining/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(), None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
                continue
            return None, f"HTTPError {e.code}: {e}"
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return None, f"{type(e).__name__}: {e}"
    return None, "exhausted retries"


def fetch_json(url, timeout=30, retries=3):
    raw, err = fetch_bytes(url, timeout=timeout, retries=retries)
    if err:
        return None, err
    try:
        return json.loads(raw), None
    except Exception as e:
        return None, f"bad JSON from {url}: {type(e).__name__}: {e}"


# --- Header-staging correction (NPM-CORPUS-HDR-FIX) -------------------------------------------
# Real, confirmed root cause (FINDINGS_REVIEW.md): every package in the corpus declares
# node-addon-api (sometimes nan) as an npm DEPENDENCY and #includes its header, but no
# package's own tarball vendors that header -- it is meant to resolve from
# node_modules/<dep>/ after `npm install`, which this pipeline never ran. c2cpg therefore
# could not resolve ANY Napi:: static-factory call, corpus-wide. This section fetches ONLY
# the specific declared dependency's own header-only package (not a full `npm install`: no
# scripts run, no transitive tree, no unrelated native deps built) and hands its extracted
# directory to c2cpg via --include, so #include <napi.h> / #include <nan.h> resolve exactly
# as they would after a real install.
#
# Disclosed scope, stated precisely -- this is NOT a full npm resolver:
#  - Only "node-addon-api" and "nan" are staged (the two node-addon-api-style header-only C++
#    wrapper libraries actually observed in this corpus's binding_evidence). Raw N-API usage
#    via <node_api.h>/<js_native_api.h> is NOT covered -- those are Node.js's own core
#    headers, not distributed via any npm package, and staging them would require vendoring a
#    matching Node.js headers tarball, a separate, larger undertaking not attempted here.
#  - Version resolution is a minimal, hand-written npm range matcher (exact/^/~/>=/>/<=/</*),
#    not a byte-for-byte reimplementation of npm's own resolver. It excludes prereleases and
#    falls back to the package's "latest" dist-tag if the range can't be parsed or nothing in
#    the registry's version list satisfies it -- a real, disclosed approximation, not a
#    silent guess: every resolution (or failure) is recorded in the package's own
#    `header_staging` evidence field.
#  - Staging is fail-OPEN: a missing package.json, an unresolvable range, or a failed fetch
#    means that dependency is simply not staged (recorded as such) -- c2cpg still runs
#    exactly as it did before this fix, so this correction can only ADD resolution, never
#    remove or regress any package's prior result.

NATIVE_HEADER_DEPS = ("node-addon-api", "nan")


def _parse_semver(v):
    # Strips build metadata (+...) and returns (major, minor, patch, prerelease_or_None).
    v = v.strip().lstrip("v")
    core = v.split("+", 1)[0]
    if "-" in core:
        core, pre = core.split("-", 1)
    else:
        pre = None
    parts = (core.split(".") + ["0", "0", "0"])[:3]
    try:
        major, minor, patch = (int(p) for p in parts)
    except ValueError:
        return None
    return (major, minor, patch, pre)


def _range_satisfied(ver, range_spec):
    # ver: parsed (major, minor, patch, prerelease) tuple, already prerelease-excluded by the
    # caller. Supports the common single-clause forms actually seen in real package.json
    # dependency fields: exact "X.Y.Z", "^X.Y.Z", "~X.Y.Z", ">=X.Y.Z", ">X.Y.Z", "<=X.Y.Z",
    # "<X.Y.Z", "*"/""/"latest". Anything else (OR ranges, hyphen ranges, "x" wildcards) is
    # NOT parsed -- the caller treats that as "unresolvable" and falls back to dist-tags.latest.
    spec = range_spec.strip()
    if spec in ("", "*", "latest"):
        return True
    for op, cmp_fn in ((">=", lambda a, b: a >= b), ("<=", lambda a, b: a <= b),
                        (">", lambda a, b: a > b), ("<", lambda a, b: a < b)):
        if spec.startswith(op):
            target = _parse_semver(spec[len(op):])
            return target is not None and cmp_fn(ver[:3], target[:3])
    if spec.startswith("^"):
        target = _parse_semver(spec[1:])
        if target is None:
            return None
        maj, minr, pat, _ = target
        if maj > 0:
            return (maj, minr, pat) <= ver[:3] < (maj + 1, 0, 0)
        if minr > 0:
            return (0, minr, pat) <= ver[:3] < (0, minr + 1, 0)
        return (0, 0, pat) <= ver[:3] <= (0, 0, pat)
    if spec.startswith("~"):
        target = _parse_semver(spec[1:])
        if target is None:
            return None
        maj, minr, pat, _ = target
        return (maj, minr, pat) <= ver[:3] < (maj, minr + 1, 0)
    target = _parse_semver(spec)
    if target is not None:
        return ver[:3] == target[:3]
    return None  # unrecognized range shape -- caller falls back to latest


def resolve_npm_dep_version(dep_name, range_spec):
    """Returns (resolved_version_or_None, tarball_url_or_None, note)."""
    meta, err = fetch_json(f"https://registry.npmjs.org/{dep_name}")
    if err:
        return None, None, f"metadata fetch failed: {err}"
    latest_tag = meta.get("dist-tags", {}).get("latest")
    versions = meta.get("versions", {})
    candidates = []
    for v, info in versions.items():
        parsed = _parse_semver(v)
        if parsed is None or parsed[3] is not None:  # skip unparsed / prerelease
            continue
        sat = _range_satisfied(parsed, range_spec)
        if sat is None:
            candidates = None  # unrecognized range shape -- abandon range matching entirely
            break
        if sat:
            candidates.append((parsed[:3], v))
    if candidates:
        candidates.sort()
        resolved = candidates[-1][1]
        note = f"range '{range_spec}' resolved to {resolved} (highest satisfying release)"
    elif latest_tag and latest_tag in versions:
        resolved = latest_tag
        note = f"range '{range_spec}' unresolvable/unsatisfied -- fell back to latest ({resolved})"
    else:
        return None, None, f"no satisfying version and no usable latest tag for '{range_spec}'"
    tarball = versions.get(resolved, {}).get("dist", {}).get("tarball")
    if not tarball:
        return None, None, f"resolved {resolved} but no dist.tarball in registry metadata"
    return resolved, tarball, note


def stage_native_dep_headers(pkg_dir, work_root):
    """Fetches and extracts node-addon-api/nan (whichever this package actually declares) into
    work_root/headers/<dep>/, returning (include_dirs, evidence_list) for c2cpg --include."""
    include_dirs = []
    evidence = []
    pkg_json_path = os.path.join(pkg_dir, "package.json")
    if not os.path.isfile(pkg_json_path):
        return include_dirs, [{"dep": None, "staged": False, "note": "no package.json found"}]
    try:
        with open(pkg_json_path) as f:
            pkg_json = json.load(f)
    except Exception as e:
        return include_dirs, [{"dep": None, "staged": False,
                                 "note": f"package.json unreadable: {type(e).__name__}: {e}"}]
    declared = {}
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        declared.update(pkg_json.get(field) or {})
    for dep in NATIVE_HEADER_DEPS:
        if dep not in declared:
            continue
        range_spec = declared[dep]
        resolved, tarball, note = resolve_npm_dep_version(dep, range_spec)
        if not tarball:
            evidence.append({"dep": dep, "declared_range": range_spec, "staged": False,
                              "note": note})
            continue
        tb, err = fetch_bytes(tarball)
        if err:
            evidence.append({"dep": dep, "declared_range": range_spec, "resolved_version":
                              resolved, "staged": False, "note": f"tarball fetch failed: {err}"})
            continue
        dep_dir = os.path.join(work_root, "headers", dep)
        try:
            os.makedirs(dep_dir, exist_ok=True)
            tf = tarfile.open(fileobj=__import__("io").BytesIO(tb), mode="r:gz")
            tf.extractall(dep_dir, filter="data")
            tf.close()
            inner = os.path.join(dep_dir, "package")
            if os.path.isdir(inner):
                for name in os.listdir(inner):
                    shutil.move(os.path.join(inner, name), os.path.join(dep_dir, name))
                os.rmdir(inner)
        except Exception as e:
            evidence.append({"dep": dep, "declared_range": range_spec, "resolved_version":
                              resolved, "staged": False,
                              "note": f"extract failed: {type(e).__name__}: {e}"})
            continue
        include_dirs.append(dep_dir)
        evidence.append({"dep": dep, "declared_range": range_spec, "resolved_version": resolved,
                          "staged": True, "note": note})
    if not evidence:
        evidence.append({"dep": None, "staged": False,
                          "note": "package.json present but declares neither node-addon-api nor nan"})
    return include_dirs, evidence


def find_and_classify_gyp_targets(pkg_dir):
    """R06 TARGET-SCOPING FIX -- locates this package's own real binding.gyp (searched from
    pkg_dir's root, shallowest match first -- real corpus packages observed so far keep it at
    the package root; a bounded recursive search catches the rare nested case without an
    unbounded walk) and returns (relative_gyp_path, per_target_list) via the real,
    already-tested `classify_target_aware()` parser, or (None, None) if no real binding.gyp
    exists in this package at all (a cmake/meson/gn-only package, or no native build file --
    both real, disclosed cases; the caller/scanner then falls back to the package-wide
    npm_build_configuration.tsv value, never guesses per-target)."""
    matches = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        if "binding.gyp" in filenames:
            rel_dir = os.path.relpath(dirpath, pkg_dir)
            depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
            matches.append((depth, os.path.join(dirpath, "binding.gyp")))
    if not matches:
        return None, None
    matches.sort(key=lambda t: t[0])
    gyp_path = matches[0][1]
    try:
        with open(gyp_path, "rb") as f:
            content = f.read()
    except Exception:
        return None, None
    per_target = classify_target_aware(content)
    rel_path = os.path.relpath(gyp_path, pkg_dir)
    return rel_path, (per_target or None)


def run_one(pkg_name, version, tarball_url, exception_config, work_root):
    record = {"package_name": pkg_name, "version": version, "stages": {}, "status": None,
              "detail": ""}
    pkg_dir = os.path.join(work_root, "pkg")
    js_dir = os.path.join(work_root, "js")
    work = os.path.join(work_root, "work")
    for d in (pkg_dir, js_dir, work):
        os.makedirs(d, exist_ok=True)

    t0 = time.time()
    tb, err = fetch_bytes(tarball_url)
    record["stages"]["download"] = {"seconds": time.time() - t0}
    if err:
        record["status"] = "DOWNLOAD_FAILED"
        record["detail"] = err
        return record
    # R06 BUNDLE INTEGRITY (item 4): real sha256 of the actual downloaded tarball bytes,
    # carried through on the record so main()'s own write_evidence_bundle() call can cite it
    # without re-fetching or re-hashing.
    record["tarball_sha256"] = hashlib.sha256(tb).hexdigest()

    t0 = time.time()
    try:
        tf = tarfile.open(fileobj=__import__("io").BytesIO(tb), mode="r:gz")
        tf.extractall(pkg_dir, filter="data")
        tf.close()
        # npm tarballs wrap contents under package/ -- flatten one level if present
        inner = os.path.join(pkg_dir, "package")
        if os.path.isdir(inner):
            for name in os.listdir(inner):
                shutil.move(os.path.join(inner, name), os.path.join(pkg_dir, name))
            os.rmdir(inner)
    except Exception as e:
        record["stages"]["extract"] = {"seconds": time.time() - t0}
        record["status"] = "EXTRACTION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["extract"] = {"seconds": time.time() - t0}

    # NPM-CORPUS-HDR-FIX: stage this package's own declared node-addon-api/nan headers (see
    # stage_native_dep_headers's docstring for the disclosed scope) before c2cpg runs, so
    # #include <napi.h> resolves instead of falling back to <unresolvedNamespace> for every
    # Napi:: call, as it did corpus-wide before this fix (FINDINGS_REVIEW.md).
    t0 = time.time()
    include_dirs, header_evidence = stage_native_dep_headers(pkg_dir, work_root)
    record["header_staging"] = header_evidence
    record["stages"]["header_staging"] = {"seconds": time.time() - t0,
                                            "n_staged": len(include_dirs)}

    # Collect JS/TS files into a separate dir (jssrc2cpg over the whole tree would also work,
    # but node_modules-free npm tarballs are small enough that pointing jssrc2cpg at pkg_dir
    # directly is simpler and equally correct -- use pkg_dir itself for JS, and c2cpg also
    # over pkg_dir for C/C++; both frontends only pick up their own extensions.)
    cpp_bin = os.path.join(work, "cpp.cpg.bin")
    c2cpg_cmd = [f"{JOERN_HOME}/c2cpg.sh", "-o", cpp_bin]
    for d in include_dirs:
        c2cpg_cmd += ["--include", d]
    # RESOURCE-GUARD-R05-HDR-FIX2: real napi.h #errors out (Exception support not detected)
    # unless NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS is predefined -- confirmed real,
    # see HDR_FIX_STATUS.md. Use this package's OWN already-extracted exception_config where
    # known ("disabled"/"enabled"); for "unresolved"/"conflict"/missing, define
    # NAPI_DISABLE_CPP_EXCEPTIONS anyway AS A PARSING AID ONLY -- disclosed, deliberate: this
    # maximizes real structural resolution quality (most of the corpus's KNOWN values are
    # "disabled" -- CORPUS_STATUS.md: 140 disabled vs 19 enabled -- and Cartesi/sqlite3/
    # gjsify-node-gi are all real "disabled" packages) without smuggling in an unjustified
    # verdict: R04/R05's own APPLICABILITY GATE reads this package's REAL build_config.json
    # independently and still correctly abstains (BUILD_CONFIGURATION_UNRESOLVED/_CONFLICT)
    # for any package whose real evidence doesn't establish "disabled" -- this parsing-time
    # define never substitutes for that separate, already-existing check.
    c2cpg_cmd += ["--define", "NAPI_CPP_EXCEPTIONS" if exception_config == "enabled"
                  else "NAPI_DISABLE_CPP_EXCEPTIONS"]
    c2cpg_cmd.append(pkg_dir)
    rc, secs, mem, err = run_stage(
        c2cpg_cmd,
        os.path.join(work, "cpp_gen.log"))
    record["stages"]["c2cpg"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "CPP_CPG_FAILED"
        record["detail"] = err or f"c2cpg rc={rc}"
        return record

    js_bin = os.path.join(work, "js.cpg.bin")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/jssrc2cpg.sh", "-o", js_bin, pkg_dir],
        os.path.join(work, "js_gen.log"))
    record["stages"]["jssrc2cpg"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "JS_CPG_FAILED"
        record["detail"] = err or f"jssrc2cpg rc={rc}"
        return record

    # JS FRONTEND ENTRYPOINT-COVERAGE CORRECTION (see module docstring for the full, evidence-
    # backed story -- real, confirmed severe on multi-spec-parser and node-llama-cpp). Runs here,
    # immediately after the initial jssrc2cpg build and before js_export/js_facts.json or any
    # downstream stage, and reassigns js_bin itself when a correction is applied -- every stage
    # below that reuses js_bin (js_facts.json, Nan, ReDoS, Path Traversal, Serialize DoS) then
    # transparently gets the corrected CPG, with no per-stage fix needed.
    #
    # frontend_coverage_check.py (frozen, reused verbatim, never modified) already implements and
    # validates this exact mechanism -- see its own module docstring for jssrc2cpg's own real
    # ignore-rule constants (decompiled and probe-confirmed there). js_bin ALREADY IS the "pass 1"
    # CPG its own check_package() would otherwise build itself, so pass 1 is never rebuilt here --
    # fcc.list_cpg_files() is checked directly against js_bin, and a pass-2 rebuild
    # (fcc.stage_recovered_source + fcc.build_cpg) only happens if something package.json-resolved
    # is genuinely missing. In the common case (nothing missing) js_bin is left exactly as the
    # jssrc2cpg.sh call above already built it, with zero extra CPG build.
    t0 = time.time()
    try:
        sys.path.insert(0, REDOS_FCC_AUDIT_DIR)
        import frontend_coverage_check as fcc  # noqa: E402 -- reused, never modified

        js_frontend_coverage = {"resolved_entrypoints": [], "n_missing_entrypoints": 0,
                                 "missing_entrypoints": [], "correction_applied": False}
        pkg_json_path = fcc.find_package_json(pkg_dir)
        if pkg_json_path is not None:
            with open(pkg_json_path) as f:
                pkg_doc = json.load(f)
            entrypoints = fcc.resolve_entrypoints(pkg_doc)
            # pkg_dir is ALREADY flattened (the npm tarball's own "package/" wrapper was stripped
            # above) -- pkg_root_rel is therefore "" in the common case, so entrypoint relpaths
            # need no prefix; matches frontend_coverage_check.py's own check_package() logic for
            # the pkg_root_rel == "." case.
            pkg_root_rel = os.path.relpath(os.path.dirname(pkg_json_path), pkg_dir).replace(os.sep, "/")
            if pkg_root_rel == ".":
                pkg_root_rel = ""

            def to_pkg_dir_rel(ep, _prefix=pkg_root_rel):
                return (_prefix + "/" + ep) if _prefix else ep

            cpg1_files_set = set(fcc.list_cpg_files(js_bin)[0])
            missing = []
            for ep in entrypoints:
                relpath = to_pkg_dir_rel(ep)
                if relpath in cpg1_files_set:
                    continue
                abspath = os.path.join(pkg_dir, *relpath.split("/"))
                if not os.path.isfile(abspath):
                    continue
                reason = fcc.classify_ignore_reason(relpath, abspath)
                if reason:
                    missing.append((relpath, reason))
            js_frontend_coverage["resolved_entrypoints"] = entrypoints
            js_frontend_coverage["n_missing_entrypoints"] = len(missing)
            js_frontend_coverage["missing_entrypoints"] = [
                {"relpath": r, "reason": rs} for r, rs in missing]
            if missing:
                staged_dir, recovered_map = fcc.stage_recovered_source(pkg_dir, missing)
                js_bin_corrected = os.path.join(work, "js_pass2_corrected.cpg.bin")
                ok2, log2 = fcc.build_cpg(staged_dir, js_bin_corrected)
                if ok2:
                    cpg2_files_set = set(fcc.list_cpg_files(js_bin_corrected)[0])
                    still_missing = [(r, rs) for r, rs in missing
                                      if recovered_map.get(r) not in cpg2_files_set]
                    js_frontend_coverage["correction_applied"] = True
                    js_frontend_coverage["recovered_path_map"] = recovered_map
                    js_frontend_coverage["still_missing_after_correction"] = still_missing
                    js_bin = js_bin_corrected  # the whole point: every stage below that reuses
                                                # js_bin now gets the corrected CPG.
                else:
                    js_frontend_coverage["correction_applied"] = False
                    js_frontend_coverage["correction_error"] = log2[-1000:]
        record["js_frontend_coverage"] = js_frontend_coverage
    except Exception as e:
        record["stages"]["js_frontend_coverage"] = {"seconds": time.time() - t0}
        record["status"] = "EXPORT_FAILED"
        record["detail"] = f"js frontend coverage check failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["js_frontend_coverage"] = {"seconds": time.time() - t0}

    cpp_raw = os.path.join(work, "cpp_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", f"{CPP_FRONTEND}/export_c_cpp_facts_v03.sc",
         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"],
        os.path.join(work, "cpp_export.log"))
    record["stages"]["cpp_export"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"cpp export rc={rc}"
        return record

    js_raw = os.path.join(work, "js_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", f"{JS_FRONTEND}/export_neutral.sc",
         "--param", f"cpgFile={js_bin}", "--param", f"outDir={js_raw}"],
        os.path.join(work, "js_export.log"))
    record["stages"]["js_export"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"js export rc={rc}"
        return record

    cpp_facts = os.path.join(work, "cpp_facts.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{CPP_FRONTEND}/normalize_c_cpp_facts_v03.py",
                         cpp_raw, cpp_facts], check=True, timeout=NORMALIZE_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"cpp_normalize exceeded {NORMALIZE_TIMEOUT}s (real, reproduced " \
                            "case: re2 took 127.6s on a full re-run outside this timeout -- " \
                            "large, genuinely bundled C++ codebases need the high-resource " \
                            "retry queue, not a silent drop)"
        return record
    except Exception as e:
        record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["cpp_normalize"] = {"seconds": time.time() - t0}

    js_facts = os.path.join(work, "js_facts.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{JS_FRONTEND}/normalize_joern_facts.py",
                         js_raw, js_facts], check=True, timeout=NORMALIZE_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        record["stages"]["js_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"js_normalize exceeded {NORMALIZE_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["js_normalize"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["js_normalize"] = {"seconds": time.time() - t0}

    js_facts_adapted = os.path.join(work, "js_facts_adapted.json")
    merged = os.path.join(work, "merged.json")
    t0 = time.time()
    try:
        sys.path.insert(0, SCANNER_V2 + "/npm_corpus")
        import polyglot_compat_adapter
        polyglot_compat_adapter.adapt_js_facts(js_facts, js_facts_adapted)
        subprocess.run([sys.executable, POLYGLOT, js_facts_adapted, cpp_facts, merged,
                         "--js-receiver", "bindings"], check=True, timeout=LINK_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        with open(merged) as f:
            merged_doc = json.load(f)
        xlb = merged_doc.get("cross_language_bindings", {})
        record["cross_language_bindings"] = {
            "n_registrations": len(xlb.get("registrations", [])),
            "n_linked_calls": len(xlb.get("linked_calls", [])),
            "n_unlinked_calls": len(xlb.get("unlinked_calls", [])),
        }
    except subprocess.TimeoutExpired:
        record["stages"]["polyglot_link"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"polyglot_link exceeded {LINK_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["polyglot_link"] = {"seconds": time.time() - t0}
        record["status"] = "BINDING_UNRESOLVED"
        record["detail"] = f"{type(e).__name__}: {e}"
        return record
    record["stages"]["polyglot_link"] = {"seconds": time.time() - t0}

    # R06 TARGET-SCOPING FIX: capture this package's own real binding.gyp (already extracted
    # into pkg_dir) and its real per-target classification, so the scanner can associate each
    # finding's own source file with the SPECIFIC target that compiles it, rather than the
    # package-wide npm_build_configuration.tsv value alone. package_wide is kept as the
    # required fallback for a non-gyp (cmake/meson/gn) package, or if no binding.gyp was found
    # -- never silently dropped, always present for that disclosed scope boundary.
    t0 = time.time()
    gyp_path, gyp_targets = find_and_classify_gyp_targets(pkg_dir)
    record["stages"]["gyp_target_scoping"] = {"seconds": time.time() - t0,
                                                "gyp_path": gyp_path,
                                                "n_targets": len(gyp_targets) if gyp_targets else 0}
    build_config_path = os.path.join(work, "build_config.json")
    with open(build_config_path, "w") as f:
        json.dump({"schema": "build_config/2",
                    "exception_configuration": exception_config or "unresolved",
                    "evidence": [], "citation": "from npm_build_configuration.tsv",
                    "gyp_path": gyp_path, "gyp_targets": gyp_targets}, f)

    r04_out = os.path.join(work, "r04_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_r04.py",
                         cpp_raw, r04_out, "--real", "--build-config", build_config_path],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(r04_out) as f:
            r04_doc = json.load(f)
        record["r04_classification"] = r04_doc.get("classification", {})
        record["r04_findings"] = r04_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["r04_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"r04_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["r04_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"r04 scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["r04_scan"] = {"seconds": time.time() - t0}

    # RESOURCE-GUARD-R05: run alongside R04, not instead of it -- R05's own matching path for
    # already-resolved calls is byte-for-byte R04's (see resource_guard_verdict_r05.py's own
    # module docstring), so this is a strict superset; keeping BOTH outputs, separately keyed,
    # gives a direct per-package A/B record of exactly what recovery adds, rather than
    # silently replacing R04's own recorded numbers.
    r05_out = os.path.join(work, "r05_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_r05.py",
                         cpp_raw, r05_out, "--real", "--build-config", build_config_path],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(r05_out) as f:
            r05_doc = json.load(f)
        record["r05_classification"] = r05_doc.get("classification", {})
        record["r05_findings"] = r05_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["r05_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"r05_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["r05_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"r05 scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["r05_scan"] = {"seconds": time.time() - t0}

    # RESOURCE-GUARD-R06: run alongside R04/R05, not instead of them -- same A/B discipline.
    # R06's own two corrections (target-scoped build config, source-boundary gate) are new,
    # real behavior; keeping R04/R05's own outputs unchanged lets a reader see exactly what
    # R06 adds/removes relative to both, never silently replacing prior numbers.
    r06_out = os.path.join(work, "r06_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_r06.py",
                         cpp_raw, r06_out, "--real", "--build-config", build_config_path],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(r06_out) as f:
            r06_doc = json.load(f)
        record["r06_classification"] = r06_doc.get("classification", {})
        record["r06_findings"] = r06_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["r06_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"r06_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["r06_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"r06 scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["r06_scan"] = {"seconds": time.time() - t0}

    # NAN CAPABILITY (frozen, study/nan_capability/NAN_CAPABILITY_FREEZE.md): a real, standalone
    # Resource Guard variant for the Nan binding family -- run alongside R04/R05/R06, never
    # replacing them (imports nothing from that lineage, carries no build-config applicability
    # premise of its own; see resource_guard_verdict_nan.py's own module docstring). Uses
    # js_raw directly (the raw jssrc2cpg export this function already built above, before any
    # cleanup) -- never js_facts.json, which is a normalized summary this scanner's own
    # load_js_raw() does not read. Never gated on `exception_config`/build_config_path at all.
    nan_out = os.path.join(work, "nan_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, f"{SCANNER_V2}/resource_guard_verdict_nan.py",
                         cpp_raw, js_raw, nan_out],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(nan_out) as f:
            nan_doc = json.load(f)
        record["nan_classification"] = nan_doc.get("classification", {})
        record["nan_findings"] = nan_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["nan_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"nan_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["nan_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"nan scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["nan_scan"] = {"seconds": time.time() - t0}

    # REDOS INTEGRATION (roadmap step 8, first of 4 JS/TS classes): ReDoS is fully frozen/merged
    # (R02, export_redos_npm_integ_r02.sc + redos_verdict.py) and already validated standalone by
    # study/redos_npm/pilot25/run_pilot25_r02.py -- this ports that script's own real run_one()
    # algorithm in place, reusing pkg_dir and js_bin (both already built above) instead of
    # re-downloading/re-building a separate JS-only CPG. Never modifies frontend_coverage_check.py,
    # export_redos_npm_integ_r02.sc, or redos_verdict.py -- orchestration only, exactly as
    # run_pilot25_r02.py's own module docstring states about itself. The entrypoint-coverage
    # correction run_pilot25_r02.py's own algorithm performs at this point now happens earlier,
    # shared across every JS/TS stage (see the js_frontend_coverage block right after the initial
    # jssrc2cpg build, above) -- js_bin here already reflects it.

    # R02 producer -- same joern-script shape as cpp_export/js_export above (run_stage, checked
    # via rc/err). redos_raw and pkg_dir (passed to the reducer next) are both already absolute
    # (work_root is built from an absolute "/tmp/npm_corpus_pilot/<i>" literal in main() below,
    # and pkg_dir/work are os.path.join()'d from it) -- required by redos_verdict.py's own
    # subprocess.run(..., cwd=ADJUDICATOR_DIR, ...) call to adjudicate_js.py, which silently
    # produces ADJUDICATOR_RUN_FAILED on every sink if handed a relative path instead.
    redos_raw = os.path.join(work, "redos_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", R02_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={redos_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "redos_producer.log"))
    record["stages"]["redos_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"redos producer rc={rc}"
        return record

    # Reducer (frozen, unmodified): exactly 3 positional args, both redos_raw and pkg_dir passed
    # absolute (see comment above).
    redos_out = os.path.join(work, "redos_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, REDOS_VERDICT, redos_raw, pkg_dir, redos_out],
                         check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
        with open(redos_out) as f:
            redos_doc = json.load(f)
        record["redos_classification"] = redos_doc.get("classification", {})
        record["redos_findings"] = redos_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["redos_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"redos_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["redos_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"redos scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["redos_scan"] = {"seconds": time.time() - t0}

    # PATH TRAVERSAL INTEGRATION (roadmap step 8, second of 4 JS/TS classes): two producers, in
    # order, into the SAME rawDir -- the shared npm-source-identity producer first (writes
    # source_origin_facts.tsv), then Path Traversal's own R02 producer (reads it, writes
    # source_facts.tsv/sink_abstentions.tsv/etc.). Reuses js_bin (already built above), which now
    # already reflects the shared entrypoint-coverage correction (see js_frontend_coverage above)
    # -- an earlier version of this comment claimed Path Traversal needed no such correction of
    # its own, which was WRONG: it operates over the exact same CPG ReDoS does, so a package whose
    # real code jssrc2cpg would otherwise have silently dropped (e.g. multi-spec-parser, whose
    # main resolves into dist/) was just as coverage-blind here as it was for ReDoS before this
    # fix -- confirmed real: this session's own earlier "multi-spec-parser: zero findings,
    # correctly" claim for Path Traversal was a coverage blackout, not a genuine negative.
    pt_raw = os.path.join(work, "pt_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", NPM_SOURCE_IDENTITY_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={pt_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "npm_source_identity_producer.log"))
    record["stages"]["npm_source_identity_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"npm_source_identity producer rc={rc}"
        return record

    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", PATH_TRAVERSAL_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={pt_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "path_traversal_producer.log"),
        timeout=PATH_TRAVERSAL_PRODUCER_TIMEOUT)
    record["stages"]["path_traversal_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"path_traversal producer rc={rc}"
        return record

    # Reducer (frozen except for the sink_abstentions consumption fix): 3 positional args, both
    # pt_raw and pkg_dir passed absolute (same real landmine as redos_verdict.py -- a relative
    # path here silently produces ADJUDICATOR_RUN_FAILED on every sink instead of a real error).
    pt_out = os.path.join(work, "path_traversal_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, PATH_TRAVERSAL_VERDICT, pt_raw, pkg_dir, pt_out],
                         check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
        with open(pt_out) as f:
            pt_doc = json.load(f)
        record["path_traversal_classification"] = pt_doc.get("classification", {})
        record["path_traversal_findings"] = pt_doc.get("findings", [])
        record["path_traversal_abstentions"] = pt_doc.get("abstentions", [])
    except subprocess.TimeoutExpired:
        record["stages"]["path_traversal_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"path_traversal_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["path_traversal_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"path_traversal scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["path_traversal_scan"] = {"seconds": time.time() - t0}

    # SERIALIZE DOS INTEGRATION (roadmap step 8, third of 4 JS/TS classes): Serialize DoS was
    # built by a separate, parallel session and merged into develop unmodified under its own
    # serialize-dos-r01/ directory; its own module docstring explicitly defers pipeline
    # integration ("reportable is fixed to false on every finding: pipeline integration is
    # explicitly deferred"). This is exactly that deferred integration -- orchestration only,
    # never modifying export_serialize_facts.sc, transform_presence.sc,
    # setup_candidate_multisource.sc, export_property_propagation.sc, adjudicate_js.py, or
    # serialize_dos_r03.py. Reuses js_bin/pkg_dir (both already built/extracted above), same as
    # ReDoS/Path Traversal.
    #
    # Import the frozen reducer module now (never modified, never reimplemented -- same
    # discipline run_pilot25_r02.py used for ReDoS) so its own `_pkg()` helper can be reused
    # verbatim below, rather than re-deriving the same "first path component" logic here.
    sys.path.insert(0, SERIALIZE_DOS_R01_DIR)
    import serialize_dos_r03  # noqa: E402 -- reused, never modified
    sys.path.insert(0, SCANNER_V2)
    import adjudicate_iterative  # noqa: E402 -- ADJUDICATE-ITERATIVE-R01, see its own module
                                  # docstring: drives adjudicate_js.py through every distinct
                                  # unresolved alternative at a sink, not just the first one a
                                  # single invocation happens to reach.

    # First producer pair (export_serialize_facts.sc + transform_presence.sc, into the SAME
    # sd_facts dir -- required by serialize_dos_r03.py's own derive(), which reads all four
    # fact files -- serialize_sinks.tsv/uncaught_handlers.tsv/depth_guards.tsv/
    # transform_presence.tsv -- from one shared directory).
    sd_facts = os.path.join(work, "sd_facts")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", SERIALIZE_FACTS_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"outDir={sd_facts}"],
        os.path.join(work, "sd_facts_producer.log"))
    record["stages"]["sd_facts_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"serialize facts producer rc={rc}"
        return record

    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", TRANSFORM_PRESENCE_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"outDir={sd_facts}"],
        os.path.join(work, "sd_transform_presence_producer.log"))
    record["stages"]["sd_transform_presence_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"transform presence producer rc={rc}"
        return record

    # Read serialize_sinks.tsv (8 cols: file, method, line, callee, arg, attacker, in_try,
    # bounded_literal) directly, a small local TSV read, to decide whether the (expensive)
    # taint-engine sub-pipeline is needed at all -- matching serialize_dos_r03.py's own derive()
    # gating condition exactly (is_attacker and not bounded): "if is_attacker and not bounded
    # and taint_evidence_dir is not None". Most packages have zero qualifying rows -- the common,
    # cheap, correct case -- and skip straight to the derive() call below with
    # taint_evidence_dir=None.
    sd_qualifying_pkgs = set()
    sinks_tsv = os.path.join(sd_facts, "serialize_sinks.tsv")
    try:
        if os.path.isfile(sinks_tsv):
            with open(sinks_tsv) as f:
                for line in f:
                    if not line.strip():
                        continue
                    cols = line.rstrip("\n").split("\t")
                    if len(cols) != 8:
                        continue
                    file_, _meth, _line, _callee, _arg, attacker, _in_try, bounded_lit = cols
                    if attacker == "true" and bounded_lit == "false":
                        sd_qualifying_pkgs.add(serialize_dos_r03._pkg(file_))
    except Exception as e:
        record["stages"]["sd_sink_scan"] = {"seconds": 0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"serialize_sinks.tsv read failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["sd_sink_scan"] = {"n_qualifying_pkgs": len(sd_qualifying_pkgs)}

    # Taint-engine sub-pipeline: run once per DISTINCT _pkg(file) key among qualifying sinks
    # (almost always exactly one for a single-package scan, but handled generally). Each key gets
    # its own sd_taint_raw/<key> (setup_candidate_multisource.sc + export_property_propagation.sc)
    # and its own sd_taint_evidence/<key>/evidence_final.json (adjudicate_js.py) -- exactly the
    # subpath serialize_dos_r03.py's own derive() looks up internally via taint_evidence_dir / pkg
    # / "evidence_final.json".
    sd_taint_raw_base = os.path.join(work, "sd_taint_raw")
    sd_taint_evidence_base = os.path.join(work, "sd_taint_evidence")
    sd_adjudication_loop_by_key = {}  # key -> {rounds_asked, rounds_answered,
                                       #         unaddressed_alternative_count}, for attaching
                                       # onto serialize_dos_r03.derive()'s own per-finding
                                       # dicts below (it never computes this itself).
    for key in sorted(sd_qualifying_pkgs):
        taint_raw = os.path.join(sd_taint_raw_base, key)
        rc, secs, mem, err = run_stage(
            [f"{JOERN_HOME}/joern", "--script", SETUP_CANDIDATE_MULTISOURCE_PRODUCER,
             "--param", f"cpgFile={js_bin}", "--param", f"rawDir={taint_raw}",
             "--param", f"srcPattern={SERIALIZE_DOS_SRC_PATTERN}"],
            os.path.join(work, f"sd_setup_candidate_multisource_{key.replace(os.sep, '_')}.log"))
        record["stages"][f"sd_setup_candidate_multisource[{key}]"] = {
            "seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
        if err or rc != 0:
            record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
            record["detail"] = err or f"setup_candidate_multisource rc={rc} (pkg={key})"
            return record

        rc, secs, mem, err = run_stage(
            [f"{JOERN_HOME}/joern", "--script", PROPERTY_PROPAGATION_PRODUCER,
             "--param", f"cpgFile={js_bin}", "--param", f"rawDir={taint_raw}"],
            os.path.join(work, f"sd_property_propagation_{key.replace(os.sep, '_')}.log"))
        record["stages"][f"sd_property_propagation[{key}]"] = {
            "seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
        if err or rc != 0:
            record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
            record["detail"] = err or f"export_property_propagation rc={rc} (pkg={key})"
            return record

        # ADJUDICATE-ITERATIVE-R01: invoked here since serialize_dos_r03.py's own reducer does
        # NOT call adjudicate_js.py internally (unlike ReDoS/Path Traversal, whose reducers
        # handle this themselves). ask_fn=None keeps external behavior byte-for-byte the same
        # as the single direct subprocess.run() call this replaced (still asks only the FIRST
        # unresolved alternative at this sink, still never fabricates an answer) -- the one
        # real change is that this now discloses, into record["stages"], how many OTHER
        # distinct alternatives at this sink were never even asked about, instead of that gap
        # being silent (see adjudicate_iterative.py's own module docstring for why this is a
        # real gap: a sink fed by more than one distinct unresolved source-to-sink path
        # otherwise only ever surfaces the first one). TCH_SINK and TCH_SINK_KIND are still
        # deliberately left unset -- "first established" sink and "JSON.stringify" are already
        # the documented defaults every existing Serialize DoS fixture and the real motifer
        # validation rely on (confirmed against property_configs/serialize_dos.json's own
        # direct_sink_kinds above).
        taint_out_dir = os.path.join(sd_taint_evidence_base, key)
        os.makedirs(taint_out_dir, exist_ok=True)
        t0 = time.time()
        evidence, adj_err = adjudicate_iterative.run_adjudicate_sink_iterative(
            ADJUDICATOR_DIR, taint_raw, pkg_dir, taint_out_dir, SERIALIZE_DOS_PROPERTY_CONFIG,
            ask_fn=None, timeout=SCAN_TIMEOUT)
        if evidence is None:
            record["stages"][f"sd_adjudicate[{key}]"] = {"seconds": time.time() - t0}
            record["status"] = "NORMALIZATION_FAILED"
            record["detail"] = f"sd adjudicate_js.py failed (pkg={key}): {adj_err}"
            return record
        loop_stats = evidence.get("_adjudication_loop", {})
        record["stages"][f"sd_adjudicate[{key}]"] = {"seconds": time.time() - t0, **loop_stats}
        sd_adjudication_loop_by_key[key] = loop_stats

    # Reducer (frozen, unmodified): imported and called directly, never reimplemented, matching
    # run_pilot25_r02.py's own "import and orchestrate" discipline for ReDoS. taint_evidence_dir
    # is the PARENT sd_taint_evidence dir (derive() appends _pkg(...) internally) -- None when no
    # qualifying sink existed, so the taint-engine sub-pipeline was correctly, cheaply skipped.
    t0 = time.time()
    try:
        sd_taint_evidence_dir = sd_taint_evidence_base if sd_qualifying_pkgs else None
        sd_result = serialize_dos_r03.derive(sd_facts, sd_taint_evidence_dir)
        # ADJUDICATE-ITERATIVE-R01: serialize_dos_r03.derive() itself is frozen and never
        # computes this -- attached here, orchestration-only, from the per-key loop stats
        # already captured above (finding["package"] is derive()'s own real _pkg(file) value,
        # the same key this stage used for its own sd_taint_evidence/<key> subdirectory).
        for finding in sd_result.get("findings", []):
            loop_stats = sd_adjudication_loop_by_key.get(finding.get("package"), {})
            finding["unaddressed_alternative_count"] = loop_stats.get("unaddressed_alternative_count")
        record["serialize_dos_classification"] = sd_result.get("classification")
        record["serialize_dos_findings"] = sd_result.get("findings", [])
        # serialize_dos_out.json -- same real bundling precedent as redos_out.json/
        # path_traversal_out.json (evidence_bundle.py's own BUNDLED_RELATIVE_PATHS).
        sd_out = os.path.join(work, "serialize_dos_out.json")
        with open(sd_out, "w") as f:
            json.dump(sd_result, f)
    except Exception as e:
        record["stages"]["sd_reduce"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"serialize_dos_r03.derive() failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["sd_reduce"] = {"seconds": time.time() - t0}

    # LLM-INPUT INTEGRATION: producer (frozen, standard cpgFile/outDir signature) against js_bin
    # -- already reflects the shared entrypoint-coverage correction (see js_frontend_coverage
    # above), same as every other JS/TS stage -- then the reducer (frozen, unmodified): imported
    # and called directly, matching the "import and orchestrate, never reimplement" discipline
    # already established for serialize_dos_r03/ReDoS. Unlike Serialize DoS, no adjudicator/
    # semantic-review step exists for this property at all -- derive() is fully structural.
    llm_raw = os.path.join(work, "llm_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", LLM_FACTS_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"outDir={llm_raw}"],
        os.path.join(work, "llm_facts_producer.log"))
    record["stages"]["llm_facts_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"llm facts producer rc={rc}"
        return record

    t0 = time.time()
    try:
        sys.path.insert(0, ADJUDICATOR_DIR)
        import llm_input_verdict  # noqa: E402 -- reused, never modified

        llm_result = llm_input_verdict.derive(llm_raw)
        # llm_input_verdict.py's own findings carry no "reportable" field at all (it was built
        # and gated standalone, before this pipeline's own "every finding is reportable=False
        # pending broader validation" convention existed) -- set here, orchestration-only,
        # never inside the frozen reducer, same discipline as Serialize DoS's own
        # unaddressed_alternative_count attachment above.
        for finding in llm_result.get("findings", []):
            finding["reportable"] = False
        record["llm_input_findings"] = llm_result.get("findings", [])
        # llm_input_out.json -- same real bundling precedent as redos_out.json/
        # path_traversal_out.json/serialize_dos_out.json (evidence_bundle.py's own
        # BUNDLED_RELATIVE_PATHS).
        llm_out = os.path.join(work, "llm_input_out.json")
        with open(llm_out, "w") as f:
            json.dump(llm_result, f)
    except Exception as e:
        record["stages"]["llm_input_reduce"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"llm_input_verdict.derive() failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["llm_input_reduce"] = {"seconds": time.time() - t0}

    # NOSQLI INTEGRATION: producer (frozen except NOSQLI-INTEG-R01-FIX01's additive column fix,
    # see the module-level comment above) against js_bin -- already reflects the shared
    # entrypoint-coverage correction, same as every other JS/TS stage -- then the reducer (new
    # this session, orchestration-only: imports adjudicate_iterative exactly as redos_verdict.py/
    # path_traversal_verdict.py do, never reimplements adjudicate_js.py or the producer's own
    # Stage 1/2/3 logic).
    nosqli_raw = os.path.join(work, "nosqli_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", NOSQLI_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={nosqli_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "nosqli_producer.log"))
    record["stages"]["nosqli_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"nosqli producer rc={rc}"
        return record

    # Reducer: 3 positional args, both nosqli_raw and pkg_dir passed absolute (same real landmine
    # as redos_verdict.py/path_traversal_verdict.py -- a relative path here silently produces
    # ADJUDICATOR_RUN_FAILED on every sink instead of a real error).
    nosqli_out = os.path.join(work, "nosqli_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, NOSQLI_VERDICT, nosqli_raw, pkg_dir, nosqli_out],
                         check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
        with open(nosqli_out) as f:
            nosqli_doc = json.load(f)
        record["nosqli_classification"] = nosqli_doc.get("classification", {})
        record["nosqli_findings"] = nosqli_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["nosqli_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"nosqli_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["nosqli_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"nosqli scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["nosqli_scan"] = {"seconds": time.time() - t0}

    # SSRF INTEGRATION: producer (frozen except SSRF-INTEG-R01-FIX01's additive column fix, see
    # the module-level comment above) against js_bin -- already reflects the shared entrypoint-
    # coverage correction, same as every other JS/TS stage. browserSourceTsv deliberately omitted
    # (default "") -- see the module-level comment for why the WebExtension bridge is out of
    # scope for a generic npm-library corpus scan.
    ssrf_raw = os.path.join(work, "ssrf_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", SSRF_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={ssrf_raw}",
         "--param", f"srcLabel={pkg_name}"],
        os.path.join(work, "ssrf_producer.log"))
    record["stages"]["ssrf_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"ssrf producer rc={rc}"
        return record

    # Reducer: 3 positional args, both ssrf_raw and pkg_dir passed absolute (same real landmine
    # as every other reducer in this pipeline -- a relative path here silently produces
    # ADJUDICATOR_RUN_FAILED on every sink instead of a real error).
    ssrf_out = os.path.join(work, "ssrf_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, SSRF_VERDICT, ssrf_raw, pkg_dir, ssrf_out],
                         check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
        with open(ssrf_out) as f:
            ssrf_doc = json.load(f)
        record["ssrf_classification"] = ssrf_doc.get("classification", {})
        record["ssrf_findings"] = ssrf_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["ssrf_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"ssrf_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["ssrf_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"ssrf scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["ssrf_scan"] = {"seconds": time.time() - t0}

    # FIVE-MORE-CLASSES INTEGRATION (see the module-level comment above for the full
    # disclosure): a small shared helper runs each class's producer(s) then its verdict.py,
    # since all five follow the exact same cpgFile/outDir producer convention and single-raw-dir
    # (or root+raw-dir, for Malicious NPM) reducer convention -- orchestration only, no class-
    # specific logic lives here beyond the module_export_identity.sc prerequisite and the extra
    # root argument Malicious NPM's own derive() needs for manifest red flags.
    #
    # All five verdict.py's expose the SAME importable derive() shape llm_input_verdict.py does
    # (confirmed by reading each one: guard_fallthrough_verdict.derive(raw),
    # globalmut_verdict.derive(raw), denylist_bypass_verdict.derive(raw),
    # validation_bypass_verdict.derive(raw), malicious_npm_verdict.derive(root, raw) -- their own
    # `if __name__ == "__main__"` blocks are just a thin CLI wrapper around the same call) -- so
    # this imports and calls derive() directly, matching the "import and orchestrate, never
    # shell out to a subprocess" discipline already established for llm_input_verdict.py/
    # serialize_dos_r03.py, rather than the subprocess+stdout-capture indirection an earlier
    # draft of this stage used.
    sys.path.insert(0, GATES_DIR)

    def run_gates_class(key, producers, module_name, needs_pkg_root=False):
        raw_dir = os.path.join(work, f"{key}_raw")
        os.makedirs(raw_dir, exist_ok=True)
        for label, sc in producers:
            rc, secs, mem, err = run_stage(
                [f"{JOERN_HOME}/joern", "--script", sc,
                 "--param", f"cpgFile={js_bin}", "--param", f"outDir={raw_dir}"],
                os.path.join(work, f"{key}_{label}_producer.log"))
            record["stages"][f"{key}_{label}_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
            if err or rc != 0:
                return ("RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED",
                        err or f"{key} {label} producer rc={rc}")
        t0 = time.time()
        try:
            module = importlib.import_module(module_name)  # reused, never modified
            result = module.derive(pkg_dir, raw_dir) if needs_pkg_root else module.derive(raw_dir)
        except Exception as e:
            record["stages"][f"{key}_reduce"] = {"seconds": time.time() - t0}
            return ("NORMALIZATION_FAILED", f"{module_name}.derive() failed: {type(e).__name__}: {e}")
        record["stages"][f"{key}_reduce"] = {"seconds": time.time() - t0}
        # None of these five verdict.py's own findings carry a "reportable" field at all (same
        # "predates the convention" shape as llm_input_verdict.py) -- set here, orchestration-
        # only, never inside the frozen reducer. Unlike llm_input, each of these five's own
        # findings mix CANDIDATE_* and SAFE_* rows together (their derive() doesn't pre-filter),
        # so the CANDIDATE-only filter has to happen here too, before reportable is attached.
        candidates = [f for f in result.get("findings", []) if str(f.get("verdict", "")).startswith("CANDIDATE")]
        for finding in candidates:
            finding["reportable"] = False
        record[f"{key}_findings"] = candidates
        # {key}_out.json -- same real bundling precedent as llm_input_out.json/redos_out.json
        # (evidence_bundle.py's own BUNDLED_RELATIVE_PATHS), written here rather than relying on
        # any of the five verdict.py's own stdout (none of them take an output-file argument).
        out_path = os.path.join(work, f"{key}_out.json")
        with open(out_path, "w") as f:
            json.dump(result, f, default=str)
        return (None, None)

    t0 = time.time()
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", MODULE_EXPORT_IDENTITY_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"outDir={os.path.join(work, 'guard_fallthrough_raw')}"],
        os.path.join(work, "guard_fallthrough_module_export_identity_producer.log"))
    record["stages"]["guard_fallthrough_module_export_identity_producer"] = {
        "seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"guard_fallthrough module_export_identity producer rc={rc}"
        return record
    status, detail = run_gates_class(
        "guard_fallthrough", [("export_guard_facts", GUARD_FALLTHROUGH_PRODUCER)], "guard_fallthrough_verdict")
    if status:
        record["status"] = status
        record["detail"] = detail
        return record

    # Global Singleton Mutation shares the SAME module_export_identity.sc prerequisite, run into
    # its own separate raw dir (never sharing guard_fallthrough_raw -- each class's own raw dir
    # stays self-contained, matching every other property in this pipeline).
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", MODULE_EXPORT_IDENTITY_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"outDir={os.path.join(work, 'globalmut_raw')}"],
        os.path.join(work, "globalmut_module_export_identity_producer.log"))
    record["stages"]["globalmut_module_export_identity_producer"] = {
        "seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"globalmut module_export_identity producer rc={rc}"
        return record
    status, detail = run_gates_class(
        "globalmut", [("export_globalmut_facts", GLOBALMUT_PRODUCER)], "globalmut_verdict")
    if status:
        record["status"] = status
        record["detail"] = detail
        return record

    status, detail = run_gates_class(
        "denylist_bypass", [("export_denylist_facts", DENYLIST_BYPASS_PRODUCER)], "denylist_bypass_verdict")
    if status:
        record["status"] = status
        record["detail"] = detail
        return record

    status, detail = run_gates_class(
        "validation_bypass", [("export_loop_facts", VALIDATION_BYPASS_PRODUCER)], "validation_bypass_verdict")
    if status:
        record["status"] = status
        record["detail"] = detail
        return record

    # Malicious NPM Install Exfil's own derive(root, raw) needs the package's own source root
    # too (manifest red flags read package.json directly) -- the one class of these five whose
    # derive() takes two positional args, not one.
    status, detail = run_gates_class(
        "malicious_npm", [("export_mal_facts", MALICIOUS_NPM_PRODUCER)], "malicious_npm_verdict",
        needs_pkg_root=True)
    if status:
        record["status"] = status
        record["detail"] = detail
        return record

    # ESCAPE-PARITY-BOUNDARY INTEGRATION (see module-level comment above for the full
    # disclosure): producer uses the cpgFile/rawDir convention (ReDoS/Path Traversal/NoSQLi/
    # SSRF's own shape), not run_gates_class()'s hardcoded outDir convention, so this is a
    # standalone block rather than a run_gates_class() call -- but the reducer side follows
    # llm_input_verdict's own no-adjudicator "import and call derive(raw_dir) directly"
    # discipline exactly, not path_traversal_verdict.py's/ssrf_verdict.py's own
    # adjudicate_iterative-driven template.
    ep_raw = os.path.join(work, "escape_parity_raw")
    rc, secs, mem, err = run_stage(
        [f"{JOERN_HOME}/joern", "--script", ESCAPE_PARITY_PRODUCER,
         "--param", f"cpgFile={js_bin}", "--param", f"rawDir={ep_raw}"],
        os.path.join(work, "escape_parity_producer.log"))
    record["stages"]["escape_parity_producer"] = {"seconds": secs, "maxrss_delta_kb": mem, "rc": rc}
    if err or rc != 0:
        record["status"] = "RESOURCE_LIMIT" if err == "TIMEOUT" else "EXPORT_FAILED"
        record["detail"] = err or f"escape_parity producer rc={rc}"
        return record

    t0 = time.time()
    try:
        sys.path.insert(0, ESCAPE_PARITY_DIR)
        import escape_parity_chain  # noqa: E402 -- reused, never modified

        ep_result = escape_parity_chain.derive(ep_raw, "JAVASCRIPT")
        # ep_result["findings"] carries every parser-layer site (CANDIDATE/NEGATIVE/ABSTAINED,
        # enriched with a `chain` sub-object) -- derive() does not pre-filter, same "filter here"
        # discipline the five-more-classes stage above already uses for its own derive() calls.
        # reportable is already False on every record inside the frozen reducer itself
        # (escape_parity_sites.py's own base() helper sets it directly), so nothing needs
        # setting here, unlike llm_input/the five more classes, whose own findings predate that
        # convention.
        ep_candidates = [f for f in ep_result.get("findings", [])
                          if f.get("classification") == "ESCAPE_PARITY_PARSER_CANDIDATE"]
        record["escape_parity_findings"] = ep_candidates
        # escape_parity_out.json -- same real bundling precedent as every other *_out.json
        # (evidence_bundle.py's own BUNDLED_RELATIVE_PATHS) -- written here, not relying on any
        # stdout, matching every prior stage's own convention.
        ep_out = os.path.join(work, "escape_parity_out.json")
        with open(ep_out, "w") as f:
            json.dump(ep_result, f, default=str)
    except Exception as e:
        record["stages"]["escape_parity_reduce"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"escape_parity_chain.derive() failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["escape_parity_reduce"] = {"seconds": time.time() - t0}

    # LOCK_BALANCE / PROTECTED_FIELD (see module-level comment above): CLI subprocess, raw TSV
    # dir in, JSON out -- the same convention R04/R05/R06's own scan stages already use.
    lb_out = os.path.join(work, "lock_balance_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, LOCK_BALANCE_VERDICT, cpp_raw, lb_out],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(lb_out) as f:
            lb_doc = json.load(f)
        record["lock_balance_classification"] = lb_doc.get("classification", {})
        record["lock_balance_findings"] = lb_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["lock_balance_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"lock_balance_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["lock_balance_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"lock_balance scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["lock_balance_scan"] = {"seconds": time.time() - t0}

    pf_out = os.path.join(work, "protected_field_out.json")
    t0 = time.time()
    try:
        subprocess.run([sys.executable, PROTECTED_FIELD_VERDICT, cpp_raw, pf_out],
                        check=True, timeout=SCAN_TIMEOUT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE)
        with open(pf_out) as f:
            pf_doc = json.load(f)
        record["protected_field_classification"] = pf_doc.get("classification", {})
        record["protected_field_findings"] = pf_doc.get("findings", [])
    except subprocess.TimeoutExpired:
        record["stages"]["protected_field_scan"] = {"seconds": time.time() - t0}
        record["status"] = "RESOURCE_LIMIT"
        record["detail"] = f"protected_field_scan exceeded {SCAN_TIMEOUT}s"
        return record
    except Exception as e:
        record["stages"]["protected_field_scan"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"protected_field scan failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["protected_field_scan"] = {"seconds": time.time() - t0}

    # OOB_WRITE / OOB_INDEX_WRITE / OOB_READ / OOB_COMPARE (see module-level comment above):
    # in-process via each module's own real emit_candidates(cpp_facts_path), matching
    # run_diagnostic_100.py's own run_scanner_json() precedent -- avoids four extra subprocess
    # spawns per package. {"candidates": [...]} written to disk for evidence-bundle parity with
    # every other property's own *_out.json.
    sys.path.insert(0, OOB_TOOLS_DIR)
    for _mod_name, _key, _fname in (
            ("oob_write_verdict", "oob_write_candidates", "oob_write_out.json"),
            ("oob_index_write_verdict", "oob_index_write_candidates", "oob_index_write_out.json"),
            ("oob_read_verdict", "oob_read_candidates", "oob_read_out.json"),
            ("oob_compare_verdict", "oob_compare_candidates", "oob_compare_out.json")):
        _stage_name = _mod_name.replace("_verdict", "_scan")
        t0 = time.time()
        try:
            # importlib is already imported at module level (line 60) -- a local `import
            # importlib` here would make it a function-local cell for this whole run_one()
            # function and break run_gates_class()'s own earlier closure reference to it
            # (confirmed as a real bug: NameError "cannot access free variable 'importlib'"
            # on guard_fallthrough_reduce, which runs before this block).
            _mod = importlib.import_module(_mod_name)
            _cands = _mod.emit_candidates(cpp_facts)
            with open(os.path.join(work, _fname), "w") as f:
                json.dump({"candidates": _cands}, f)
            record[_key] = _cands
        except Exception as e:
            record["stages"][_stage_name] = {"seconds": time.time() - t0}
            record["status"] = "NORMALIZATION_FAILED"
            record["detail"] = f"{_mod_name} scan failed: {type(e).__name__}: {e}"
            return record
        record["stages"][_stage_name] = {"seconds": time.time() - t0}

    # PROVENANCE + REACHABILITY + STAGED ENABLEMENT (tasks #35, #32, #36-40): applied once, over
    # the whole record, after every producer above (including R04/R05/R06/Nan) has run. Also
    # closes a real, previously-disclosed gap: this file has never called provenance.enrich_
    # record() before, so r04_findings/r05_findings/r06_findings/nan_findings have never had a
    # `reportable` field at all (resource_guard_verdict_r06.py's own module comment: "reportable
    # is not yet set at that point" before this call -- confirmed by direct grep before writing
    # this). finalize_reportability() uses setdefault for scanner_candidate/applicability_status/
    # adjudication_status (never overwrites an existing value) and only ever narrows -- never
    # promotes -- an already-affirmative value, so this is safe to introduce here for the first
    # time rather than a behavior change to something already relied upon.
    t0 = time.time()
    try:
        prov_manifest = provenance.build_source_manifest(pkg_dir, tb, pkg_name, version)
        provenance.enrich_record(record, cpp_raw, prov_manifest, pkg_dir)
        with open(js_facts_adapted) as f:
            js_doc = json.load(f)
        with open(cpp_facts) as f:
            cpp_doc = json.load(f)
        reachability_tier.classify_record_reachability(record, js_doc, cpp_doc)
        staged_enablement.enforce_staged_enablement(record)
    except Exception as e:
        record["stages"]["staged_property_enrichment"] = {"seconds": time.time() - t0}
        record["status"] = "NORMALIZATION_FAILED"
        record["detail"] = f"provenance/reachability/staged_enablement failed: {type(e).__name__}: {e}"
        return record
    record["stages"]["staged_property_enrichment"] = {"seconds": time.time() - t0}

    record["status"] = "ANALYZED"
    return record


def main():
    if len(sys.argv) < 5:
        raise SystemExit(
            "usage: run_pipeline_one_r06.py <eligible_path> <build_config_path> <out_path> "
            "<bundle_dir> [start_idx] [end_idx]\n"
            "bundle_dir is required and explicit -- the persistent evidence-bundle output "
            "directory (see evidence_bundle.py). Not optional: this is the whole point of "
            "the R06 persistence fix over the frozen run_pipeline_one.py."
        )
    eligible_path = sys.argv[1]
    build_config_path = sys.argv[2]
    out_path = sys.argv[3]
    bundle_dir = sys.argv[4]
    start_idx = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    end_idx = int(sys.argv[6]) if len(sys.argv) > 6 else None

    rows = []
    with open(eligible_path) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            rows.append(parts)

    exc_config_by_pkg = {}
    with open(build_config_path) as f:
        bheader = next(f).rstrip("\n").split("\t")
        bidx = {n: i for i, n in enumerate(bheader)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            exc_config_by_pkg[(parts[bidx["package_name"]], parts[bidx["version"]])] = \
                parts[bidx["exception_configuration"]]

    if end_idx is None:
        end_idx = len(rows)
    rows = rows[start_idx:end_idx]

    mode = "a" if start_idx > 0 else "w"
    with open(out_path, mode) as out:
        for i, parts in enumerate(rows):
            pkg = parts[idx["package_name"]]
            version = parts[idx["version"]]
            tarball_url = parts[idx["tarball_url"]]
            exc_config = exc_config_by_pkg.get((pkg, version))
            work_root = f"/tmp/npm_corpus_pilot/{start_idx + i}"
            shutil.rmtree(work_root, ignore_errors=True)
            os.makedirs(work_root, exist_ok=True)
            t0 = time.time()
            rec = run_one(pkg, version, tarball_url, exc_config, work_root)
            rec["total_seconds"] = time.time() - t0
            # R06 FIX: persist a minimal compressed evidence bundle BEFORE deleting work_root --
            # see evidence_bundle.py for exactly what is (and is not) kept. Bundling failure is
            # recorded, never silently swallowed, and never blocks the corpus loop from
            # continuing (a bundling bug must not turn into a lost package result).
            try:
                bundle_path, bundle_manifest = write_evidence_bundle(
                    work_root, bundle_dir, pkg, version,
                    tarball_sha256=rec.get("tarball_sha256"),
                    pipeline_status=rec.get("status"))
                rec["evidence_bundle"] = {
                    "bundle_path": bundle_path,
                    "included": bundle_manifest["included"],
                    "missing": bundle_manifest["missing"],
                    "compressed_bytes": bundle_manifest.get("compressed_bytes"),
                    "completeness_status": bundle_manifest.get("completeness_status"),
                }
            except Exception as e:
                rec["evidence_bundle"] = {"error": f"{type(e).__name__}: {e}"}
            shutil.rmtree(work_root, ignore_errors=True)  # bound disk usage -- CPG/work dir only
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"[{start_idx + i + 1}/{start_idx + len(rows)}] {pkg}@{version}: "
                  f"{rec['status']} ({rec['total_seconds']:.1f}s)", file=sys.stderr)


if __name__ == "__main__":
    main()
