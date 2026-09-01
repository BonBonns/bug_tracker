# ReDoS npm-library first pass: PACKAGE_API_INPUT_REACHABLE, reducer, and gate

Per direct instruction: scope the first ReDoS pass as detector integration plus npm public-API
reachability, NOT the RocketChat-specific source model unchanged, and NOT requiring web-request
ingress for npm libraries. Three-tier design (`REGEX_COMPLEXITY_CANDIDATE`,
`PACKAGE_API_INPUT_REACHABLE`, `APPLICATION_INGRESS_REACHABLE`), reducer + controls, new source
adapter, then validation on a historical known-positive, a disclosed development package, a blind
package, and a small token-selected sample -- in that order. This document covers all of it,
precisely and honestly.

## What was kept frozen, unchanged

The sink-identification (Stage 1) and regex-complexity classification (Stage 2) logic --
`export_redos_integ.sc`'s own real, fixture-verified functions -- is copied byte-for-byte into
the new producer (`export_redos_npm_integ.sc`), never modified. The RocketChat
`Meteor.methods`/`req.*`/`message.*` source model is likewise copied verbatim as a SEPARATE,
still-independent `APPLICATION_INGRESS` source family -- never generalized into the npm rule, per
direct instruction.

## New: PACKAGE_API_INPUT_REACHABLE source adapter

**Real, empirically-grounded design** (a 10-file Joern CPG covering every required export shape
was built and directly inspected BEFORE any detection code was written -- never guessed; see
`study/redos_npm/fixtures/README.md`):

- `module.exports = <function/arrow/anonymous expression>` -- js2cpg resolves this DIRECTLY to a
  MethodRef, no indirection.
- `module.exports.NAME = <identifier>` / `exports.NAME = <identifier>` -- resolved when that
  identifier has EXACTLY ONE prior `identifier = <MethodRef>` assignment in the same enclosing
  scope (a hoisted named function declaration, or `const foo = () => ...`).
- `module.exports["NAME"]` / `exports["NAME"]` (indexAccess, LITERAL string key) -- resolved the
  same as a named fieldAccess export.
- **Confirmed directly**: js2cpg desugars BOTH CommonJS named-function exports AND every required
  ESM shape (`export function foo(){}`, `export const foo = () => {}`, `export default function
  foo(){}`) into this EXACT SAME `identifier = MethodRef` + `exports.foo = identifier` pattern --
  no separate ESM-specific code path was needed at all.
- **Abstained, never guessed** (each confirmed via a real fixture, not assumed): a NON-literal
  (dynamic/computed) export key (`module.exports[key] = fn`); an identifier resolving to a CALL
  rather than a MethodRef (`module.exports = require(...)`, a real re-export shape); an identifier
  with zero or more than one prior MethodRef assignment; an identifier resolving to a class's own
  `<init>` (`module.exports = SomeClass` -- the constructor is NOT the class's real public API,
  its other instance methods are, and this shape is explicitly not given partial credit).
- Interprocedural propagation from an exported parameter reuses Joern's own `reachableByFlows`
  engine (same one already proven for the frozen `APPLICATION_INGRESS` model) -- never hand-rolled.
  An unresolved/dynamic callee has no real CALL-graph edge to traverse, so "abstain on unproven
  interprocedural edges" falls out of the engine's own real behavior.

## Reducer (`redos_verdict.py`)

Reduces `adjudicate_js.py`'s own real `evidence_final.json` (run once per ESTABLISHED sink) into
the standard shape:
```json
{
  "property": "REDOS",
  "classification": "PACKAGE_API_INPUT_REACHABLE",
  "regex_complexity": "CANDIDATE",
  "source_boundary": "EXPORTED_FUNCTION_PARAMETER",
  "application_ingress": "NOT_ESTABLISHED",
  "reportable": false
}
```
A finding is emitted ONLY when a sink has BOTH `REGEX_COMPLEXITY_CANDIDATE` (Stage 1/2's own
DANGEROUS classification) AND `PACKAGE_API_INPUT_REACHABLE` -- an npm library's own dangerous
regex that's unreached from its public API, or reached ONLY via a web-framework source this
package doesn't itself define, is correctly never promoted (counted separately as
`APPLICATION_INGRESS_ONLY_NOT_PROMOTED`, never silently dropped).

`reportable` is HARDCODED `false` on every finding, per direct instruction: "Enable reporting only
after a real npm package exercises the complete exported-input-to-regex path and survives manual
review." No gate or heuristic computes it in this pass.

Reads `source_facts.tsv` directly (not solely `evidence_final.json`) for a sink's FULL set of
`origin_family` values -- `adjudicate_js.py`'s own `build_evidence_v0()` only ever surfaces the
FIRST source alternative's family (`srcf[0][3]`) into its own output, confirmed by direct
inspection; a sink reached by both families would silently lose the second family's membership if
the reducer relied on `evidence_final.json` alone.

## Gate: `check_redos_verdict.py` -- 19/19 (14 synthetic + 5 real historical differential, below)

Runs against FROZEN real Joern output (`study/redos_npm/fixtures/raw/`, produced by
`export_redos_npm_integ.sc` over `fixtures/src/`'s own 10 files -- reproduces without needing
Joern again, same convention as `study/lockcap/`). Covers all four required control kinds:

- **positive** -- 6 real exported-function-param-to-DANGEROUS-regex paths (CommonJS direct/named,
  both required ESM shapes, ESM default) -- all correctly classified, `reportable=false`.
- **fixed-negative** -- `safe_export.js`'s fully-anchored allowlist regex: sink correctly excluded
  from the DANGEROUS set entirely, never emitted.
- **ordinary-negative** -- `noreach_export.js`'s exported function whose own param never reaches
  the file's separate (unexported-reachable) dangerous regex: zero rows for it.
- **abstention** (3 real, distinct shapes) -- class-constructor export, dynamic/computed export
  key, `require()` re-export: all three correctly contribute zero rows, confirmed structurally
  (`SINKS_WITH_ANY_ESTABLISHED_SOURCE == 7`, not the 11 total dangerous-eligible sinks the fixture
  set contains).
- **two-tier promotion rule** -- `meteor_ingress_only.js`'s Meteor.methods-registered-but-never-
  exported handler: reaches a DANGEROUS sink via `APPLICATION_INGRESS` alone, correctly counted
  (`APPLICATION_INGRESS_ONLY_NOT_PROMOTED`) but NEVER promoted to a finding.
- Plus a synthetic (non-corpus) Python-level control on `families_by_sink()` itself, proving a
  sink reached by BOTH families keeps both tags rather than collapsing to one.

## Historical known-positive validation -- two levels

**Level 1, copy fidelity** (pattern-only): the frozen Stage 1/2 logic's own COPY (inside the new
file) was run against the exact two real, disclosed regex patterns the property was originally
built from, wrapped in a realistic-but-synthetic npm export shape
(`study/redos_npm/historical_check/`) -- confirming the copy-paste preserved the frozen logic's
behavior exactly, not just re-deriving analytically. This level alone does NOT prove end-to-end
behavior on the actual historical package, and is not claimed to.

    CVE-2025-5892 pattern (isolated):  /^:|\s+:/               -> DANGEROUS (confirmed)
    autotranslate.ts pattern (isolated): /^\s*<p>|<\/p>\s*$/gm  -> DANGEROUS (confirmed)
    a fully-anchored allowlist (negative control): /^(https?:\/\/)?[a-z0-9.-]+$/ -> SAFE (confirmed)

**Level 2, the real historical package differential** (`study/redos_npm/historical_real/` --
the actual next deliverable, not the pattern-only check above): the ACTUAL vulnerable and fixed
versions of the file CVE-2025-5892 was assigned against, run through the complete real
producer -> `adjudicate_js.py` -> `redos_verdict.py` chain.

**Real target**: RocketChat/Rocket.Chat,
`apps/meteor/app/irc/server/servers/RFC2813/parseMessage.js`, CVE-2025-5892, fixed in
[PR #35711](https://github.com/RocketChat/Rocket.Chat/pull/35711). Vulnerable file fetched at the
real parent commit `72725d391e79b44e7380ee2fe640e2e4426c77ca`; fixed file fetched at the real fix
commit `cd5c60eeb5b68ec5a57b6a7e579def9abbfd79ab`. Real change confirmed directly in the fetched
files: `line.search(/^:|\s+:/)` -> `line.search(/^:(?<!\s)\s+:/)` (negative lookbehind added).
Both use the real export shape `module.exports = function parseMessage(line) { ... }`.

| | sink targets | DANGEROUS | `redos_verdict.py` result |
|---|---|---|---|
| **vulnerable** (`72725d3`) | 7 | 1 (L52) | **1 finding, `PACKAGE_API_INPUT_REACHABLE`, `reportable=false`** |
| **fixed** (`cd5c60e`, PR #35711) | 7 | 0 | **0 findings** |

Exactly the required result: the vulnerable version produces `PACKAGE_API_INPUT_REACHABLE`; the
fixed version does not -- on the real file, real commits, real CVE, through the complete chain.
Frozen as `check_redos_verdict.py` regression controls (`REDOS_VERDICT_R01=19/19`, up from 14/14).

## Correction: the four-package search was exploratory, not a pre-registered protocol

**The four packages below (validator, marked, braces, ms) were selected manually, one at a time,
each after seeing the prior package's own result influence the next choice -- this does NOT
satisfy a disclosed-development/frozen-blind sequence, and this document originally described it
as though it did. Corrected here explicitly, not silently rewritten.** They remain useful as
export-adapter validation on real, structurally-diverse production code (Babel/ESM-interop
exports, a UMD/IIFE wrapper, a plain anonymous-function export) -- that finding stands -- but they
are relabeled EXPLORATORY, and are superseded as the pre-registered discovery mechanism by the
frozen 25-package pilot below.

| Package | Real shape exercised | Sinks | DANGEROUS | Exports resolved | Result |
|---|---|---|---|---|---|
| `ms@0.7.3` | `module.exports = function(...)` | 1 | 0 | -- | pattern IS fully-anchored, no alternation -- correctly SAFE per this heuristic's own disclosed narrow scope |
| `validator@5.0.0` | Babel-transpiled `exports.default = <identifier>`, real production code | 61 | 0 | 59 real exports correctly resolved (+ 66 correct abstentions on the package's own second `module.exports = exports['default']` indexAccess-RHS line) | no DANGEROUS pattern present |
| `marked@0.3.19` | `module.exports = marked` inside a real UMD wrapper/IIFE | 110 | 0 | 1/1 correctly resolved through the IIFE scope | no DANGEROUS pattern present |
| `braces@1.8.5` | `module.exports = function(...)` (anonymous) | 9 | 0 | 1/1 correctly resolved | no DANGEROUS pattern present |

## Frozen 25-package discovery pilot (pre-registered, not manual selection)

Full protocol, selection script, and frozen selection artifact: `study/redos_npm/pilot25/README.md`
+ `pilot25_selection.json` + `pilot25_selection_provenance.json` (corpus/prefilter integrity
hashes, selection criteria, and selected package/version identities -- see "Pre-registration
integrity" below). 21 packages were **`PREFILTER_SELECTED`** against a 25 ceiling -- an input set
for deeper analysis, never itself a ReDoS finding -- selection committed BEFORE any of them was
Joern-scanned. Full categorized results and manual review: `pilot25/pilot25_categorized_results.json`,
`pilot25/PILOT25_MANUAL_REVIEW.md`.

**Real result, by category** (21 `PREFILTER_SELECTED` -> 21 `PIPELINE_ANALYZED`, 0
`INFRASTRUCTURE_FAILURE` -- a path bug in the orchestration script, not the analyzer, caused every
package to fail on the first attempt; fixed, verified in isolation, re-run -> 14
`NO_COMPLEXITY_CANDIDATE`, 6 `COMPLEXITY_ONLY`, **1 `PACKAGE_API_INPUT_REACHABLE`**): the one
record that reached `PACKAGE_API_INPUT_REACHABLE` (`phplike@2.5.12`'s own `sprintf()`,
`string.js:209`) was the only one to proceed to manual review, per protocol. Reviewed by direct
timing measurement (not reasoning alone, matching the property's own established discipline):
confirmed LINEAR scaling up to 80,000 adversarial characters (sub-millisecond throughout, no
quadratic or exponential growth) -- **`MANUALLY_REJECTED`**, a confirmed false positive, not a
real ReDoS. Root cause formalized and stress-tested
(`pilot25/phplike_review/ROOT_CAUSE_AND_DECISION.md`): the dangerous branch's own quantifier is
gated behind a LITERAL `%` that is character-class-DISJOINT from what it quantifies (`\d`) --
confirmed decisive by direct timing proof that an OVERLAPPING gating literal (common or not)
reproduces the same real quadratic blowup CVE-2025-5892 shows. **Fix-vs-adjudicate decision:
ADJUDICATION** -- a safe general fix needs real character-class disjointness analysis (a
genuinely new capability, not a small patch; an unsafe shortcut has been directly shown to risk
real false negatives) -- not attempted here, since the analyzer was not modified after the
pre-registered selection was committed, per direct instruction. 0 records were
`MANUALLY_CONFIRMED`; 0 were `ABSTAINED`.

**No `PACKAGE_API_INPUT_REACHABLE` record was `MANUALLY_CONFIRMED`** -- per direct instruction
point 8, this is reported as the measured result, not silently absorbed. Pipeline wiring and
`reportable` enablement (points 9-10) both stay out of scope for this round as a direct
consequence: no record from this pilot cleared manual review to justify either.

### Pre-registration integrity (`pilot25_selection_provenance.json`)

Added retroactively after the pilot completed, per direct instruction -- attests to the SAME
already-frozen `pilot25_selection.json` (unmodified; its own `selected` list is unchanged),
verified directly against git history rather than re-derived:

- **Corpus identity**: `npm_corpus/eligible_packages.tsv`, sha256
  `4ed7c11d3617f77af79fd6716e08fbc552ded0ced30390c4e5f739a83fa72680` (git blob
  `b98837158497c1cc8c7d84c480598dcd8e50197e`), as of commit `04c0d5f6`. Verified directly (not
  assumed): 495 total lines = 1 header + 494 data rows; 494 unique `package_name`+`version`
  identities (zero duplicates); all 494 rows `status=ANALYZED`.
- **Prefilter implementation identity**: `prefilter_select_25.py`, sha256
  `b68616732cb95387aebbc24f4019d9861b572d1b55f78d0f47771d8fc358a866` (git blob
  `561fbc0d65c21ac09237f7b0f3812376c912dec6`), as of the same commit.
- **Exact selection criteria**: candidate pool = all 494 `ANALYZED` rows; required ALL of (an
  exported-function-shaped statement; a regex literal; a DANGEROUS-shaped literal per a direct
  Python port of the frozen Stage 2 classifier); score = count of DANGEROUS-shaped literals; max
  25 selected; ties by ascending `row_index` (frozen corpus order).
- **Selected package/version identities**: all 21, listed verbatim in
  `pilot25_selection_provenance.json`.

## What remains, explicitly out of this pass's scope

- **Pipeline wiring** (`run_pipeline_one.py`/`run_diagnostic_100.py`, `provenance.py`'s
  `PROPERTY_CANDIDATE_RULES`/`enrich_record` key tuple, `evidence_bundle.py`'s
  `BUNDLED_RELATIVE_PATHS`/`ANALYZER_FILES`, `staged_enablement.py`'s `ENABLED_PROPERTIES`,
  `six_property_aggregator.py`) -- this pass is reducer + new source adapter + gate only, per
  direct instruction; the npm corpus pipeline itself is untouched.
- **`reportable` computation** -- hardcoded `false`; no gate has been built to flip it, per direct
  instruction ("enable reporting only after a real npm package exercises the complete path and
  survives manual review" -- that real npm package has not yet been found).
- `export_redos_npm_integ.sc` still never populates `transform_identity.tsv` (same real,
  already-disclosed gap the original `export_redos_integ.sc` has -- redos's own direct-dataflow
  shape genuinely has no transform step to report, per `RUNBOOK.md`'s own "0 rounds" note,
  confirmed again here).
- A genuine "wild" real npm positive (DANGEROUS regex + real PACKAGE_API_INPUT reachability on an
  UNMODIFIED real package) was searched for but not found in this pass's four-package sample --
  real future work, not silently deferred.

## Bounded precision/coverage audit, before pipeline integration

Per direct instruction: root-cause `phplike`'s rejection, categorize the pilot's own 6
`COMPLEXITY_ONLY` and 14 `NO_COMPLEXITY_CANDIDATE` records, fix the prefilter if justified using
the 21 pilot packages strictly as the development/regression set, freeze, then select a genuinely
new blind package set before viewing outcomes. Full detail in `pilot25/audit/`.

**1. `phplike` root cause** (`pilot25/phplike_review/ROOT_CAUSE_AND_DECISION.md`): the real
variable is character-class DISJOINTNESS between a branch's gating literal and its quantified
atom, not literal rarity/frequency as first (wrongly) framed -- corrected explicitly after a
stress test (`overlap_test.js`) showed an OVERLAPPING gating literal reproduces real quadratic
blowup even when common. Decision: **ADJUDICATION**, not a structural fix -- a safe fix needs a
genuinely new character-class-disjointness capability; an unsafe shortcut was shown, not assumed,
to risk false negatives.

**2. `COMPLEXITY_ONLY` categorization** (`pilot25/audit/COMPLEXITY_ONLY_CATEGORIZATION.md`): 5 of
6 `GENUINELY_INTERNAL_REGEX` (install-lifecycle/CLI scripts never reachable from the real runtime
entrypoint, or internal subprocess-output parsing); 1 `PUBLIC_EXPORT_RESOLUTION_GAP`
(`velociradix`'s `Context.graphql()` -- a real, disclosed, unattempted design gap: the adapter has
no path to resolve a class's own instance methods as export sources, nor to trace `this`-field
taint from a constructor's real parameters -- future work, not attempted in this bounded pass).

**3. Prefilter/classifier divergence** (`pilot25/audit/PREFILTER_DIVERGENCE_AUDIT.md`): ~82% of
the 14-package divergence traces to jssrc2cpg's own real default file/folder exclusions
(decompiled from `jssrc2cpg-4.0.608.jar`, confirmed by synthetic-probe testing) that the
prefilter's own file filter never replicated; the remainder to a JSDoc-comment misparse. This is a
**prefilter-only** precision issue -- the real Joern classifier was correct throughout, it simply
never saw these excluded files either.

**4-5. Fix, regression, and freeze** (`pilot25/audit/PREFILTER_FIX.md`): implemented file-exclusion
parity + comment stripping in `prefilter_select_25.py`. The first comment-stripper version
introduced a real regression -- caught by its own regression test
(`pilot25/audit/validate_prefilter_fix.py`) before anything was frozen: a string literal
containing `'*/*'` (an Accept-header wildcard check) in `velociradix`'s real source was misread as
a comment-open delimiter, silently deleting ~9,000 characters of real code including its own
genuine dangerous regex literal. Root-caused precisely and fixed with a provably-sound
string-literal-aware linear scanner. Re-validated: **7/7 real positives detected, zero
regressions**. Two pre-existing, disclosed false positives (`ssh2`, `mariasql`) left unfixed --
real def-use/call-target resolution is out of this cheap prefilter's documented scope, and
over-counting is its accepted-safe direction. `prefilter_select_25.py` at this state is frozen.

**6. New blind package set** (`pilot25/select_blind2.py`, `pilot25/pilot_blind2_selection.json`):
ran the corrected prefilter over the same frozen 494-package corpus, package NAMES from the 21
already used as the development/regression set excluded (473 rows scanned). **Result: 0
qualifying packages, 0 selected -- all 473 rows processed cleanly (zero fetch/extract failures).**
A real, measured zero, not silently absorbed, matching the discipline instruction B point 8 set
out in advance ("if no real candidate appears, report the measured zero"). With the file-exclusion
and string-literal-aware fixes in place, the corrected prefilter finds no export-reachable
DANGEROUS-shaped regex literal anywhere in the remaining corpus -- consistent with the divergence
audit's own finding that most of the original pilot's proxy-positive score came from now-excluded
files. Whether the frozen Stage 2 complexity model itself is too narrow (as instruction B point 8
anticipates as a live possibility) is a real, open question this bounded audit does not resolve --
flagged for the next phase, not integration.

**Net state after this audit**: the ReDoS property remains fully implemented, historically
validated (real CVE-2025-5892 differential), and precision-audited (both the 21-package pilot's
own imperfections and the prefilter's own imperfections are root-caused and either fixed or
disclosed). **No real npm package has yet produced a `MANUALLY_CONFIRMED` finding.**
`reportable` stays hardcoded `false`; no pipeline wiring has been touched. Real-corpus precision
validation is measurably further along; production pipeline integration remains explicitly not
started.
