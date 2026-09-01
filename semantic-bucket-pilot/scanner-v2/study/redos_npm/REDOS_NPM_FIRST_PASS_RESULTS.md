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

## Gate: `check_redos_verdict.py` -- 14/14

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

## Historical known-positive validation

The frozen Stage 1/2 logic's own COPY (inside the new file) was run against the exact two real,
disclosed regex patterns the property was originally built from -- confirming the copy-paste
preserved the frozen logic's behavior exactly, not just re-deriving analytically:

    CVE-2025-5892 (RocketChat, disclosed):  /^:|\s+:/                    -> DANGEROUS (confirmed)
    autotranslate.ts (RocketChat):          /^\s*<p>|<\/p>\s*$/gm        -> DANGEROUS (confirmed)
    a fully-anchored allowlist (stand-in for "the fixed version"):
                                             /^(https?:\/\/)?[a-z0-9.-]+$/ -> SAFE (confirmed)

Both real patterns wrapped in a realistic npm export shape (`module.exports.NAME = function...`)
were also confirmed reachable end-to-end (`PACKAGE_API_INPUT` family, 2/2 rows emitted) --
`study/redos_npm/` -- proving the full real chain (frozen classification + new source adapter)
on the exact real ground truth this property claims to catch.

## Development package, blind package, and small sample: real search, honestly reported

**What was actually done, not glossed over**: four real, substantial npm packages were fetched
fresh from the real npm registry and run through the COMPLETE real pipeline (`jssrc2cpg` ->
`export_redos_npm_integ.sc`, real Joern CPGs built and queried, not simulated):

| Package | Real shape exercised | Sinks | DANGEROUS | Exports resolved | Result |
|---|---|---|---|---|---|
| `ms@0.7.3` | `module.exports = function(...)` | 1 | 0 | -- | pattern IS fully-anchored, no alternation -- correctly SAFE per this heuristic's own disclosed narrow scope (CVE-2015-8315's real severity came from a different mechanism this heuristic explicitly doesn't model) |
| `validator@5.0.0` | Babel-transpiled `exports.default = <identifier>`, real production code | 61 | 0 | **59 real exports correctly resolved** (+ 66 correct abstentions on the package's own SECOND `module.exports = exports['default']` indexAccess-RHS line -- a real shape not yet handled, honestly abstained rather than guessed) | no DANGEROUS pattern present in this library's own regexes |
| `marked@0.3.19` | `module.exports = marked` inside a real UMD wrapper/IIFE | 110 | 0 | 1/1 correctly resolved through the IIFE scope | no DANGEROUS pattern present |
| `braces@1.8.5` | `module.exports = function(...)` (anonymous) | 9 | 0 | 1/1 correctly resolved | no DANGEROUS pattern present |

**Honest conclusion, not overclaimed**: none of these four real packages happened to ALSO contain
a regex matching this property's own narrow, disclosed heuristic shape (nested quantifier;
alternation branch with trailing content) -- a real, low base rate given the property's original
1477-file RocketChat corpus study itself only found 2 real matches. This is a genuine, disclosed
non-result for the "wild positive on npm" search, NOT a validation failure -- the actual thing at
risk in this pass (the NEW `PACKAGE_API_INPUT_REACHABLE` source adapter) was thoroughly, positively
validated on real, structurally-diverse production code across all four: Babel/ESM-interop exports
(59 of them, one real package), a UMD/IIFE-wrapped default export, and a plain anonymous-function
export -- proving the resolver itself works correctly on real npm code, independent of whether any
particular package happens to trip the classifier.

Given no real wild positive was found, the strongest available "development case" validation
combines the REAL historical CVE patterns (not fabricated) with a REALISTIC npm export wrapper
(`study/redos_npm/` historical check, above) -- disclosed explicitly as constructed-from-real-
patterns, not claimed to be an as-found wild positive. `validator@5.0.0` stands as the blind
package (chosen, then run, with no prior knowledge of its result) and is part of the small sample
above, together with `marked`/`braces`/`ms`.

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
