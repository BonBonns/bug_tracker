# MOZ-POS-R01 — sourcing log + memory-boundary inventory (pre-scan, R03 frozen)

## A. Memory-safety boundary inventory (correcting the earlier overstatement)
TChecker DOES have C/C++ memory-safety analysis. Verified in the bundle:
- Facts: `.memory.json` (memory_locations), `.reachingdef.json`, `.bound.json`
  (bounds tagged SOURCE_CAPACITY / DEST_CAPACITY), plus role sidecars.
- Candidate producers: tools/oob_read_verdict.py and tools/oob_write_verdict.py each
  emit {class: OOB_READ|OOB_WRITE, verdict: CANDIDATE} (never VULNERABLE), with real
  abstention discipline (guard-presence-alone can't clear; STATIC_EXTENT_SAFE = sizeof(dst)
  suppresses; unknown source-capacity abstains). Validated by the guard-r01 gate on a live
  fixed-buffer over-read corpus (simdissdk-style `mix_fixed` read -> exactly 1 candidate).

PRECISE MISSING LAYER (not "memory analysis"):
  1. No adjudicator integration: OOB candidates are terminal deterministic tools in tools/.
     There is NO property_configs/* for OOB and NO OOB -> llm_input semantic-review handoff.
     (Adjudicator classes today: nosqli, path_traversal, redos, serialize_dos, ssrf.)
  2. No Gecko-specific memory modeling: the OOB producer keys on generic fixed C buffers +
     sizeof, not Gecko containers/APIs (nsTArray, mozilla::Span, mozalloc, memcpy wrappers).

## B. Sourcing status (frozen R03; classes = ssrf, redos, serialize_dos, nosqli, path_traversal)
Key PRE-SCAN finding: Mozilla's DISCLOSED vulnerabilities have LOW overlap with TChecker's
existing five JS taint-to-sink classes.
- Firefox core: overwhelmingly memory-safety roll-ups (OOB/UAF) + principal/authorization and
  chrome-injection bugs. None are ssrf/redos/serialize_dos/nosqli/path_traversal-to-sink.
- FxA service: the CHANGELOG "redos" entries are DEPENDENCY advisories (moment date parsing),
  not first-party code -> not valid pairs.

Verified Firefox privileged-JS candidate found (labeled BROWSER, not service):
- CVE-2015-7223 / Bugzilla 1226423 "Privilege escalation in WebExtension APIs"
  file: toolkit/components/extensions/Extension.jsm ; fix changeset af47051962f8
  root cause: WebExtension APIs injected into documents without a WebExtension principal.
  CLASS MAPPING: this is a missing-principal/authorization bug -> maps to NONE of TChecker's
  current classes. Useful as an out-of-taxonomy control (expected MISS at the
  source/sink-recognition layer), NOT as a matching-property positive.

## C. Honest consequence for the plan
A 3-5 pair corpus "matching existing classes" is genuinely hard to populate from Mozilla's
disclosed set. The dominant blocker for Mozilla positives is TAXONOMY overlap (which classes
exist), not detection depth. That reinforces plan item #2 (add sink definitions, incl. wiring
the existing OOB producers into the adjudicator) BEFORE expecting a rich Mozilla positive set.
No pairs fabricated. Next: deeper archaeology in Bugzilla security bugs + npm advisories against
FxA's OWN packages for true in-taxonomy matches; and/or pin CVE-2015-7223 pre/post and run the
stage ledger as an out-of-taxonomy baseline demonstration.

## Stage-ledger template (to be filled per verified pair, once pinned)
  pair_id | label(BROWSER|SERVICE) | class | file:function | fix_commit | parent_commit
  vuln:    source_recognized? sink_recognized? source_reaches_sink? candidate_emitted? llm_packet?
  patched: candidate_suppressed?
