# Gate track naming (fixes the cross-branch Gate-number collision)

Track-prefixed IDs are canonical from here. Legacy `gateNN` directories that are
wired into run_all.py / verify_canonical_engine.sh keep their directory names for
tooling stability; this table is the authoritative mapping.

## JSTS-R — real-Joern JS/TS frontend reconstruction
| ID       | Directory        | What it proves                                             |
|----------|------------------|------------------------------------------------------------|
| JSTS-R01 | gate24, gate24-ts, gate24-ts2 | real jssrc2cpg runs; dispatch precision characterized; corrected classifier (18/18) |
| JSTS-R02 | jsts-r02 (was gate39) | keyed state (index+field) from operator structure, 11/11 vs Gate-20 truth |
| JSTS-R03 | jsts-r03 (was gate40) | identity/alias must-may joins + callee summaries + promoted dispatch, 6/6 vs Gate-13 truth |
| JSTS-R04 | jsts-r04 (was gate41) | closure capture via CLOSURE_BINDING export, 11/11 incl. two-hop nesting |
| JSTS-R05 | jsts-r05          | end-to-end: TS -> jssrc2cpg -> neutral facts -> ProgramGraphLoader -> PortableProvenanceEngine -> evidence (no PHPCGFactory) |

## JS-PROP — keyed-property provenance
| ID          | Directory     | What it proves |
|-------------|---------------|----------------|
| JS-PROP-R03 | js-prop-r03   | Canonical nested receiver identity (`root + path`) from real Joern facts; fully-literal PARAMETER/LOCAL propagation is MAY-only, while same-path overwrite, parent overwrite, dynamic parent pollution, mixed child/parent writes, dynamic path, sibling write, SELF root, and distinct-root contamination remain separated. Live frontend/engine gate `16/16`; neutral CORE-S04 gate `13/13` including schema strictness and 0.3 compatibility. |

## JS-SOURCE — browser and runtime input classes
| ID            | Directory       | What it proves |
|---------------|-----------------|----------------|
| JS-SOURCE-R02 | js-source-r02   | Direct `browser|chrome.runtime.onMessageExternal` payload parameter 0 through an inline or exactly-defined named handler. Preserves `WEBEXT_EXTERNAL_MESSAGE_INPUT` as MAY; internal messages, tabs events, browser.test, ports, sender metadata, aliases and ambiguous handlers remain separate. CORE-S05 `7/7`, frontend `10/10`, scanner `4/4`. |
| JS-SOURCE-R03 | js-source-r03   | Use-scoped WebExtension tab URL metadata: `tabs.onCreated` `tab.url`, plus `tabs.onUpdated` `changeInfo.url`/`tab.url`. Targets the individual `STATE_READ`, preserving `WEBEXT_TAB_URL_INPUT` as MAY while IDs, status, cookie-store fields, nested/sibling properties, aliases, test namespaces and ambiguous handlers remain separate. CORE-S06 `6/6`, frontend `11/11`. |

## CORE — portable-core milestones (existing gate dirs unchanged)
CORE-25..CORE-38 == gate25..gate38 (ProgramGraph boundary .. deterministic consumer).

## Legacy/prototype history (unchanged directories)
gate02..gate23 — PHP-shaped-CSV / bridge-model era. Regression artifacts + canonical
legacy engine verification only; superseded as capability proofs by JSTS-R02..R04.

## CPP-R — reserved for the C/C++ (c2cpg) track (paused until the loader exists)
CPP-R01 characterization, CPP-R02 memory location, CPP-R03 points-to, CPP-R04 indirect writes.

## JS-STATE-R — JS/TS failure-state erasure characterization (new track, post-JSTS-R05)
| ID          | Directory     | What it proves                                                                 |
|-------------|---------------|---------------------------------------------------------------------------------|
| JS-STATE-R01| js-state-r01  | Characterization only, no detector. Whether real Joern facts can represent "success/failure return -> erasing transformation -> guard on transformed value -> security-sensitive use". See `js-state-r01/JS_STATE_R01_CHARACTERIZATION.md` for the full write-up, evidence, and the narrowest sound invariant identified. |
| JS-STATE-R02| js-state-r02  | First implementation, scoped to exactly the ERASES-only invariant JS-STATE-R01 promoted. `FailureStateErasureCandidateFact` derivation (`frontends/javascript-typescript/joern-ts/failure_state_facts.py`) against a closed, spec-fixed set of coercion builtins/operators; REF-based (name-independent) guard-subject resolution promoted from characterization into the real `export_ts_facts.sc` export (`control_structures.tsv`, `condition_identifiers.tsv`). No PRESERVES/UNKNOWN detection, no security-sink classification -- both explicitly out of scope per JS-STATE-R01 Q4/Q5. `JS_STATE_R02=24/24`, real run against real Joern, no regressions to Gate 24-TS (27/27) or JSTS-R05 (8/8) from the shared export-script change. |
| JS-STATE-R03| js-state-r03  | Completes the target bug shape from JS-STATE-R01: attaches security-sensitive-sink reachability to every JS-STATE-R02 erasure candidate, via the same REF-only mechanism (argument identifier -> LOCAL -> matches the guarded local). Sink classification comes from an explicit, human-curated, EXAMPLE-ONLY profile (`frontends/javascript-typescript/joern-ts/security_sink_profile.py`) -- not inferred, not general-purpose. Vocabulary is deliberately two-valued (`SENSITIVE` / `UNKNOWN`); `UNKNOWN` is never read as "proven safe." `JS_STATE_R03=30/30` (grew from 21->25->30 across the R04/R05 follow-ups below), real run, no regressions to JS-STATE-R02 (24->26->28/28 as fixture cases were added). |
| JS-STATE-R04| (shares js-state-r02/js-state-r03 dirs, no separate gate dir) | Branch-aware fix to JS-STATE-R03: a call inside the guard's own condition-true branch (e.g. only runs when the guard *fired*) is no longer credited as reaching the guarded value on the continue path (`guard_then_branch_members.tsv`, `excluded_then_branch_calls` in the emitted fact). Along the way, found and fixed a real second bug: reachability only matched BARE identifier arguments, missing wrapped ones like `authenticate(x as number)`; fixed by generalizing to a full-AST-subtree walk of every call's arguments (`call_argument_identifiers.tsv`, mirroring the same fix already applied to guard conditions). Demonstrated with fixture case13. |
| JS-STATE-R05| (shares js-state-r02/js-state-r03 dirs, no separate gate dir) | Reassignment-aware fix: a call that only sees the guarded local AFTER a later reassignment to something else is no longer credited toward SENSITIVE (`excluded_reassigned_calls`). Uses a line-number approximation of ordering (not true CFG), explicitly documented as such. Demonstrated with fixture case14 (`id = Number(r); if (...) return; id = 42; authenticate(id);` -- the erased value never actually reaches the sink). Verified the two exclusion reasons (then-branch vs. reassignment) are correctly distinguished, not just both landing on UNKNOWN by coincidence. Still open: full CFG-dominance, loop-aware reassignment, conditionally-executed reassignment -- see `js-state-r03/JS_STATE_R03_RESULT.md`. |

## JS-REAL-R01 — real-corpus measurement pass (no engine changes)
First run of the JS-STATE pipeline (unchanged) against a real, external
codebase (`mozilla/fxa`, `packages/fxa-auth-server/lib/{routes,tokens,
crypto,oauth}`, 198 files / 77,966 LOC) rather than hand-written fixtures.
Full report: `docs/corpus-scans/js-real-r01/JS_REAL_R01_VERDICT.md`.

Headline: 1 raw erasure candidate on 50,638 calls, 0 reached a profiled
sink, and the one candidate was a false positive from a root cause
(RETURN_CONTRACT_NOT_ESTABLISHED) upstream of and independent from R04/R05's
known path/CFG approximation -- which had zero opportunities to matter on
this corpus. Also surfaced two real frontend-completeness findings: the
already-documented `.spec.*` test-file exclusion (expected), and one
unexplained, security-relevant file (`tokens/bundle.js`) silently dropped
with zero diagnostics, likely a filename-convention collision with common
build-artifact naming. Nominated next: **JS-STATE-R06 (Return-Contract
Establishment Characterization)**, not the CFG-unification work that was the
pre-scan assumption -- a deliberate evidence-driven departure, not an
oversight.

## JS-STATE-R06 — return-contract establishment characterization (no implementation)
Directly follows JS-REAL-R01's false positive. Characterizes two candidate
preconditions for JS-STATE-R02's erasure classifier, using real Joern output
and a fixture built around the actual real-code false positive plus two
isolation cases designed to separate the two signals from each other:
`js-state-r06/JS_STATE_R06_CHARACTERIZATION.md`.

- **SIGNAL A (guard shape)**: is the guard condition's own top-level CALL a
  failure-style comparison operator, not an arbitrary method call? Purely
  structural, needs no type facts. Alone, would have caught the real
  JS-REAL-R01 false positive.
- **SIGNAL B (return contract)**: does the erasing transformation's argument
  carry a `dynamicTypeHintFullName` (existing `type_hints.tsv` export,
  originally built for a different purpose) containing a union? Confirmed
  robust even against the known `createN` malformed-return-type bug from
  JS-STATE-R01, since it reads the union from the use site, not the method
  return.

Both signals proven independently necessary (neither alone sufficient) via
two isolation fixture cases built to fail exactly one signal each. Not
implemented -- explicitly recommends SIGNAL A as a hard precondition plus
SIGNAL B as positive-evidence-only (absence of a hint = UNKNOWN/abstain, not
proof of safety) if promoted to implementation, and flags an untested,
disclosed blind spot (field-access arguments never carry a type hint under
the current export, so a genuinely union-typed field would look identical to
a plain one to SIGNAL B).

## JS-STATE-R07 — return-contract + failure-guard precondition (implemented)
Implements exactly what R06 characterized, nothing broader:
`js_state_r07.py` (`frontends/javascript-typescript/joern-ts/`) requires ALL
of ERASES (R02) + failure-style guard shape (closed set: instanceOf, equals,
notEquals only -- no `.has()`/`.includes()`/custom predicates) + positive
union return-contract evidence (`type_hints.tsv`, ESTABLISHED only, never
UNKNOWN-as-safe) + guard-subject-is-transformed-value (already guaranteed by
R02's construction) + SENSITIVE sink reachability (R03/R04/R05, unchanged)
before emitting a candidate. Permanent gate:
`tests/gates/js-state-r07/JS_STATE_R07_RESULT.md`, `JS_STATE_R07=31/31`, real
run, five-case fixture (R06's four-way isolation matrix + the retained
null|number case). Zero regressions: R02 28/28, R03 30/30, Gate24-TS 27/27,
JSTS-R05 8/8, canonical Gate23 25/25.

**Exact JS-REAL-R01 replay** (same commit `e856cffd`, same scoped
directories, same frontend output reused directly): the one real-corpus
false positive (`bounce.email` template coercion / `seen.has(key)` dedup
guard) is now excluded, confirmed for the exact adjudicated reason
(`RETURN CONTRACT: NOT ESTABLISHED` + `FAILURE GUARD: NOT ESTABLISHED`), not
merely "count went to zero." Explicitly NOT read as validation of R07's
general precision -- one corpus with 0 findings does not distinguish
"correctly precise" from "too restrictive." Next: a second, independent
JS/TS corpus, no further JS-STATE changes first.

## JS-REAL-R02 — independent second-corpus generalization test (no engine changes)
`node-oauth/node-oauth2-server` @ `42367327`, 38 JS files / 3,859 LOC,
deliberately a different org, project, and framework from FxA. Full report:
`docs/corpus-scans/js-real-r02/JS_REAL_R02_VERDICT.md`.

Frontend health GOOD -- 38/38 files exported, **zero silent omissions**
(bidirectional filesystem-vs-exported diff run explicitly so FxA's
`bundle.js`-style drop could not recur unnoticed).

Result: **0 raw ERASES facts -- the chain terminated at stage one, so R07
was never evaluated and can be neither credited nor blamed.** Resolved
positively as outcome **A** (corpus contains no relevant
success|failure-return + coercion patterns): 157 `throw new ...Error`
statements vs. ZERO error-returning functions -- this project represents
failure by throwing, not by returning a union -- and only 2 of 2,807 calls
use any closed-set erasing coercion, both merely building thrown
error-message strings with no guard subject. NOT outcome B (R07 never ran),
NOT outcome C (frontend clean, type evidence present).

Evidence against R07 being overfit: its ingredients are non-vacuous on this
unrelated corpus (18 closed-set guard operators, 11 failure-capable union
type hints). But this is explicitly **not** validation -- R07 has still
never fired on real-world code in either corpus, and two silent corpora are
not two confirmations. Dominant residual shifted from FxA's
RETURN_CONTRACT (precision) to **BASE RATE / IDIOM MISMATCH** (recall).

Nominated next (not implemented): **JS-STATE-R08 -- Positive-Example Corpus
Construction / Recall Baseline.** Per the standing rule, do NOT tighten R07
further; two silent corpora mean missing positive examples, not excess
permissiveness. Also recorded separately: JS-STATE models failure only as a
*returned* value, but a large class of real JS/TS code uses `throw`/`catch`
-- whether an analogous erasure bug exists in the exception idiom is a
different bug shape and its own future characterization, not an R07
extension.

## JS-STATE-R08 — positive-example corpus construction / recall baseline (no engine changes)
Sought a real-world true positive for R07. Full report:
`docs/corpus-scans/js-state-r08/JS_STATE_R08_VERDICT.md`.

Source-confirmed one historical coercion-based auth bypass (CVE-2026-21854 /
GHSA-r8w6-9xwg-6h73, `the-hideout/tarkov-data-manager`, CVSS 9.8), verified in
the actual vulnerable commit rather than from advisory prose, with a
vulnerable/fixed pair extracted (`188f7562` -> `f188f0ab`). **R07 run unchanged
on both: 0 candidates on the vulnerable commit.**

The miss is exactly characterized from the CPG, not inferred: the value producer
is `<operator>.indexAccess` and the guard is `<operator>.equals`, with NO
closed-set coercion call and no intermediate transformed local -- the coercion
is implicit, internal to `==`'s abstract-equality semantics. R07's Signal A
would have matched; the chain failed at stage one (ERASES).
**Classification: OUT_OF_MODEL** (implicit coercion inside a comparison, vs.
R07's explicit-transformation-before-independent-guard model).

Acceptance gate applied and the corpus **REJECTED** as an evaluation corpus
(FAILURE_CAPABLE_RETURN = 0). That rejection exposed R08's key structural
finding: **Signal B is TypeScript-dependent.** Failure-capable union hints
measured: fxa (TS-heavy) present, node-oauth2-server (plain JS) 11,
tarkov-data-manager (plain JS) 0. On plain-JS corpora R07's recall approaches
zero structurally, regardless of whether the bug is present.

RECALL EVIDENCE: still zero across three real corpora. Nominated next:
**JS-STATE-R09 -- Bug-Family Re-Scoping Characterization** (characterization
only): decide from evidence between (a) explicit-coercion-before-guard (R07's
model, 0 real instances in 3 corpora), (b) implicit-coercion-inside-comparison
(1 confirmed real CVE), (c) exception-idiom failure state (2 corpora, dominant
real idiom). The one-line change that would have made R07 "catch" the CVE was
deliberately NOT taken -- that is fitting to a single example.

## JS-STATE-R09 — bug-family re-scoping characterization (no implementation)
Compares three candidate families side-by-side on real evidence. Full report:
`docs/corpus-scans/js-state-r09/JS_STATE_R09_CHARACTERIZATION.md`.

- **A (explicit state erasure, R07's model)** — synthetic support strong
  (31/31), real positives **0 across 3 corpora**. Status:
  **`SUPPORTED_LOW_BASE_RATE`** — retained, not deprecated. Sound detector,
  rare pattern.
- **B (implicit comparison coercion)** — the ONLY family with a real,
  source-confirmed, replayable positive anchor (CVE-2026-21854, CVSS 9.8).
- **C (exception-state handling)** — highest base rate by far (fxa 169
  throws/294 catches, node-oauth2 157/9, tarkov 3/41) but ZERO
  source-confirmed security evidence. Base rate alone is not a reason to
  build.

**Decisive R09 finding (FRONTEND_GAP):** `jssrc2cpg` exports `==` and `===`
as the *identical* CPG node — `name`, `methodFullName`, and `typeFullName`
all `<operator>.equals`. Verified by querying Joern directly, not just our
TSV export. Consequence: the CVE (`==`) and its official one-character fix
(`===`) are **completely indistinguishable** in current facts, so no sound
Family-B detector can be built today. Recovering the distinction by parsing
the raw `code` string is possible but lexical, fragile, and explicitly NOT
recommended.

Encouraging counter-finding: operand type-domain evidence is better than
expected. Same-domain controls (`string==string`, `number==0`) are provably
excludable, and the critical `x == null` usability risk is structurally
identifiable (right operand types as `__ecma.Null`) without source-text
matching. Dominant residual FP risk is `ANY`-typed operands.

Nominated next: **JS-STATE-R10 — Comparison-Operator Fidelity**
(measurement first, not implementation): determine whether the `==`/`===`
distinction is recoverable from jssrc2cpg at all. Acceptance test is already
built and unambiguous — R09 fixture cases B1 and B2 are byte-identical apart
from the operator, so any change separating them separates exactly the right
thing. If unrecoverable without patching Joern, Family B is blocked
indefinitely and that should be reported plainly.

## JS-STATE-R10 — comparison-operator fidelity (characterization, no implementation)
Narrowly asks whether `==`/`!=` can be distinguished from `===`/`!==` without
inferring it from arbitrary enclosing source text. Full report:
`docs/corpus-scans/js-state-r10/JS_STATE_R10_CHARACTERIZATION.md`.

**Layer 1 (semantic CPG properties): FAIL.** Full `propertiesMap` enumeration
(not just name/methodFullName/typeFullName) shows the complete property set is
`{ORDER, CODE, COLUMN_NUMBER, METHOD_FULL_NAME, LINE_NUMBER, TYPE_FULL_NAME,
DISPATCH_TYPE, NAME}` and NONE retains the token. Extends R09 by confirming the
collapse also covers `!=`/`!==` -> `<operator>.notEquals`, i.e. it is systematic
across the equality family. Also: the operator node's `COLUMN_NUMBER` marks the
start of the whole binary expression, not the operator.

**Layer 3 (structural span slicing): PASS 10/10.** Operands carry independent
line/col starts, so the operator can be extracted from the bounded gap between
`left.col + len(left.code)` and `right.col` -- categorically different from
searching `node.code`. Index convention MEASURED, not assumed: lines 1-based,
columns 0-based (an initial both-1-based run produced a visible one-char
overshoot, corrected before the acceptance run).

Adversarial matrix all recovered, each for a structural reason: string-literal
`==` lies inside the left operand's own span (never in the gap); comment `==`
IS in the gap and needs stripping *within the bounded span*; chained
`a == b === c` yields both operators independently; multiline; and TS non-null
`d! === b` (probes the overshoot risk).

```text
CLASSIFICATION: FRONTEND_GAP_CONFIRMED (semantic layer)
                + STRUCTURAL_RECOVERY_AVAILABLE (span layer)
```

R09's thesis conclusion STANDS -- the frontend does collapse the CVE operator
and its one-character fix. R10 adds that the loss is recoverable *outside* the
semantic fact layer, at a disclosed cost: requires source availability at
analysis time, requires a real bounded lexer (regex stripping was adequate for
the tested matrix but is not a proven-complete JS lexer -- regex/template
literals untested), depends on an undocumented column convention, and assumes
`code` is an unnormalized source slice.

Nominated next: **JS-STATE-R11 — Family-B Semantics Characterization**, now
unblocked (R09 supplied operand domains + null-idiom exclusion + sink use; R10
supplies operator identity). Added precondition: span recovery must be hardened
and re-tested against the four disclosed limitations before use in any promoted
fact -- R10 measured feasibility, NOT production robustness. Dominant residual
risk for Family B remains R09's, not R10's: `ANY`-typed operands are pervasive
in real JS (the CVE's own left operand is `ANY`), so "not proven same domain"
is far too weak to serve as positive evidence.

## JS-STATE-R11 — Family-B operand-domain semantics characterization (no implementation)
Asks what POSITIVE evidence can prove two `==` operands sit in different
coercion domains. Full report:
`docs/corpus-scans/js-state-r11/JS_STATE_R11_CHARACTERIZATION.md`.

**Permanent invariant established:** `ANY`/unknown is NOT a domain
(`ANY != OBJECT != MIXED` => `DOMAIN_NOT_ESTABLISHED`). Treating "types not
proven equal" as evidence of difference degenerates into "`==` is suspicious,"
which is unusable in plain JS.

Domain evidence measured across 7 cases: STRONG for literals, TS-annotated
locals, and literal-initialized consts; PARTIAL for producer history (via REF
to the producing assignment); WEAK for `dynamicTypeHintFullName` (empty on
almost every comparison operand -- it populates for return values, which is
why it carried R07's Signal B but does not carry Family B).

**New positive result:** index-access base recovery WORKS. `users[name]` types
as `ANY`, but its BASE carries a fully-resolved index signature
`{ [x: __ecma.String]: __ecma.String; }`, giving `LEFT_DOMAIN = STRING`
structurally.

**And that is exactly why the CVE stays undetectable.** The vulnerability
exists because `users["__proto__"]` returns `Object.prototype` -- an OBJECT
value the declared `Record<string,string>` says cannot occur. Perfect declared
-type recovery yields STRING, so the CVE classifies as `DOMAIN_UNKNOWN`, and
would classify as `NONCOERCIVE` if the right operand were annotated. Better
type evidence moves the known positive FURTHER from detection.

Nullish idiom confirmed as a hard negative tooth: structurally identifiable
(right operand LITERAL with `typeFullName = __ecma.Null`), excluded even when
the domain relation reads UNKNOWN vs NULLISH.

**Family B status: `BLOCKED_ON_DOMAIN_EVIDENCE`** -- blocked on coverage
(`ANY` dominates real cases) AND on soundness direction (better evidence gets
the one confirmed positive more wrong). Detecting the real CVE needs
prototype-chain reachability (CWE-1321), a different family.

Nominated next: **JS-STATE-R12 — Value-Domain Inference Layer**
(characterization) as the general capability the evidence keeps pointing at;
alternative **R12b — Prototype-Reachability Characterization** if the goal is
specifically the confirmed CVE. Family A remains `SUPPORTED_LOW_BASE_RATE`.
Neither family should be promoted on current evidence.

## JS-STATE-R12 — prototype-reachable property read characterization (no implementation)
Chosen over generic value-domain inference because R11 showed better declared-
domain evidence does not solve the positive anchor and can increase confidence
in the WRONG abstraction. Full report:
`docs/corpus-scans/js-state-r12/JS_STATE_R12_CHARACTERIZATION.md`.

Tests `DECLARED_VALUE_DOMAIN != RUNTIME_LOOKUP_DOMAIN` over a 9-case fixture.

**Strong results:**
- Base discrimination works: ordinary object literals
  (`{ [x: __ecma.String]: __ecma.String; }`) vs `Object.create:<returnValue>`
  are structurally distinguishable.
- `Object.create(null)` is PROVABLE from positive evidence — the argument is a
  LITERAL with `typeFullName = __ecma.Null` (not inferred from callee name).
- **Map negative control excluded BY CONSTRUCTION**: `m.get(input)` never
  produces an `<operator>.indexAccess` node (it lowers to fieldAccess + call),
  so a property-read fact model cannot accidentally absorb Map's storage
  model. Structural exclusion, not a name blocklist.
- `hasOwn` / `hasOwnProperty.call` guards are recognizable control structures;
  existing R04 then-branch machinery would establish "blocked on surviving
  path." Closed-set idiom recognition (policy), not inference.

**The blocker, precisely localized:** `KEY_CONTROLLED` is NOT establishable.
T3 (attacker-selected key) and T8 (explicitly uncontrolled key) are
indistinguishable — both non-literal keys resolving via REF to a binding.
This is the load-bearing tooth: `PROTOTYPE_VALUE_POSSIBLE` must never by
itself imply a security claim.

**CVE replay (T9): every link in the chain is establishable EXCEPT key
control** — base prototype reachable, key not provably own, no guard on path,
runtime domain (STRING|OBJECT) exceeds declared (STRING), coercion via R10,
auth decision via existing sink profile. Decisively better than R11, where the
missing evidence pointed the WRONG WAY rather than merely being absent.

Nominated next: **JS-STATE-R13 — JS/TS Source/Taint Provenance
Characterization.** R12 independently re-derived the same gap JS-REAL-R01
recorded (no JS/TS source profile exists; only the C++ track has SOURCE-R02),
which is good evidence it is the real next dependency. Prototype reachability
is tracked as a DISTINCT family (CWE-1321-shaped), not an extension of B.

**Thesis conclusion corrected** (R11's phrasing overreached — declared types
were not false, they correctly described intended values; the error was
treating them as exhaustive):
> A declared type is positive evidence about intended values, not proof that
> runtime semantics cannot produce values outside that domain.

## JS-STATE-R13 — JS/TS source provenance characterization (no implementation)
Closes the gap R12 localized: can key/value provenance from external request
surfaces be established WITHOUT using names as evidence? Full report:
`docs/corpus-scans/js-state-r13/JS_STATE_R13_VERDICT.md`.

**All framework-identity links ESTABLISHED**, verified on both a fixture and
the REAL CVE source:
- import identity (ESM + CJS)
- **framework API identity via `methodFullName`** -- the decisive finding:
  `express:<returnValue>:post`, and on the real anchor
  `express:express:<returnValue>:post` with `app` typed
  `express:express:<returnValue>`. This is Joern TYPE-RECOVERY provenance
  resolving `app` back through `express()` to the import -- NOT name matching,
  which is what makes the old rejected `function(req,res)` heuristic
  unnecessary.
- route registration, callback identity (METHOD_REF inline; identifier
  `typeFullName` for by-reference handlers, T7)
- **parameter role POSITIONALLY** (idx1 after implicit `this`) -- proven
  name-independent because two lambdas use `req`/`res` vs `request`/`response`
  in the SAME positions
- property paths, with source families kept SEPARATE (body/query/params/
  headers/cookies/process.env/process.argv are distinct paths, not collapsed)
- destructuring FOLLOWABLE (`({body},res)` lowers to `body = param1_0.body`)
- aliasing FOLLOWABLE (standard REF assignment chain)

**T2 is the load-bearing negative control and it holds.** `function fake(req,
res){ use(req.body.username) }` is byte-equivalent to the real handler in every
respect a name- or shape-based heuristic could see -- same param names, arity,
`ANY` types, same property path. The ONLY discriminator is framework
registration. Name-based reasoning gets T2 wrong; registration-based reasoning
gets it right.

**R12 anchor replay on the real vulnerable commit: SOURCE_PROVENANCE
ESTABLISHED.** Every link in the historical CVE chain (source -> prototype-
reachable read -> coercive comparison -> auth decision) is now expressible
from real facts. Explicitly NOT called a detection: nothing was promoted,
assembled, or corpus-validated.

**DOMINANT GAP: framework COVERAGE, not mechanism.** Everything rests on Joern
resolving the framework import through to `methodFullName`, verified for
Express/Router ONLY. Fastify/Koa/Hapi/NestJS/serverless, dynamic registration,
middleware-wrapped and re-exported handlers are ALL UNMEASURED. Secondary:
`process.env`/`argv` and event-payload families have distinguishable paths but
no registration anchor, so they were NOT shown establishable.

Nominated next: **JS-PROV-R01 — Shared JS/TS External-Input Origin Layer**
(characterization), deliberately renamed OUT of the JS-STATE namespace. If it
works it is shared infrastructure (SSRF, path traversal, SQLi, XSS, prototype
access, auth logic), not a bug-family component. Promoted artifact must be a
neutral `ExternalInputOriginFact`, never `attacker_controlled = true` -- the
security reader decides. Unrecognized framework must yield UNKNOWN, never
"not external".

## JS-PROV-R01 — shared external-input provenance coverage characterization (no promotion)
Measures how broadly R13's provenance mechanism generalizes across frameworks.
Full report: `docs/corpus-scans/js-prov-r01/JS_PROV_R01_VERDICT.md`.
Deliberately OUTSIDE the JS-STATE namespace: shared infrastructure, not a
bug-family component.

**Framework object identity resolves for ALL frameworks via type recovery**, and
separates the negative control by TYPE SHAPE rather than name:
`express:<returnValue>` / `express:Router:<returnValue>` / `fastify` / `koa` /
`@hapi/hapi:server:<returnValue>` vs `notFramework` =
`{ post: (p: ANY, cb: ANY) => ANY; }` (object-literal type, not module-derived).

Results: **EXPRESS/ROUTER/FASTIFY ESTABLISHED**; **KOA PARTIAL** (ctx context
model needs its own property-family mapping -- `ctx.request.body` nested,
`ctx.cookies.get()` is a CALL); **HAPI PARTIAL** (handler nested in an object
literal, needs member traversal); **SERVERLESS NOT ESTABLISHABLE** (no import,
no registration, only an export NAME -- correctly abstains).

**Unplanned strongest finding: NESTJS works via a SECOND, INDEPENDENT
mechanism** -- class/method/parameter ANNOTATIONS (`@Controller`, `@Post`,
`@Body`, `@Query`, `@Param`, `@Headers`). This is MORE precise than positional
inference because the annotation names the origin family directly. A shared
layer must model both mechanisms, not assume the Express shape generalizes.

Negative controls **6/6 silent**. Aliasing + all destructuring forms
ESTABLISHED (lower to REF-traceable assignments via `_tmp_N`). Middleware
chains and named handler references ESTABLISHED. **Concrete boundary found:**
a single alias re-export (`const reexported = namedHandler`) collapses the
function type to `ANY` and BREAKS provenance -- characterized, not patched.

```text
PROMOTION_JUSTIFIED: NO -- narrowly. 4 of 5 formal gates MET (>=2 framework
families, negative controls silent, non-name identity, alias/destructuring
preservation, unknown-framework abstention). Withheld for ONE reason: every
non-Express result rests on minimal fixtures. JS-STATE-R07 already showed
31/31 synthetic can mean 0 real positives across 3 corpora.
```

DOMINANT GAP: real-code validation breadth, not mechanism. Nominated next:
**JS-PROV-R02 — Multi-Framework Real-Code Provenance Validation** (scan >=2
real repos on different frameworks; per-repo handler recognition counts +
manual adjudication of recognized AND unrecognized samples). Promote
`ExternalInputOriginFact` only if fixtures survive production code. The layer
must never emit `attacker_controlled = true` -- it reports origin; the
security reader decides.

## JS-PROV-R02 — real-code provenance validation (no promotion)
Two independent real repos, two independent mechanisms. Full report:
`docs/corpus-scans/js-prov-r02/JS_PROV_R02_VERDICT.md`.

```text
CORPUS A: gobeam/truthy @ 9b9a61be (NestJS, 131 TS, 6410 LOC) - ANNOTATION
CORPUS B: paralect/koa-api-starter @ 19b1a265 (Koa, 58 JS, 1613 LOC) - REGISTRATION
Frontend: 131/131 and 58/58 exported, ZERO silent omissions in both.
```

**ANNOTATION provenance VALIDATED on real code**: 7/7 controllers, 39/39 route
methods located, 33/33 parameter-bearing handlers recognized (the 6 "partial"
genuinely take zero params - correct abstention). Origin-family counts an
EXACT match to source ground truth: BODY=16/16, QUERY=6/6, PARAM=12/12,
HEADERS=0/0. Manual adjudication 10/10 correct, including multi-annotation
handlers (`@Param`+`@Body`) correctly decomposed into two origins. Non-HTTP
decorators (`@GetUser`, `@UploadedFile`, `@Req`, `@Res`) resolved but NOT
claimed as input origins.

**REGISTRATION provenance REFUTED on this real corpus**: 0/14 recognized. All
14 registrations located and handler identity resolves to exact method
fullNames -- but `router` types as `ANY`, severing framework identity. Single
bounded root cause (14/14): the router is constructed in one module and passed
across a module boundary as a parameter (`require('./sign-in').register(router)`).
This is EXACTLY the alias/re-export boundary R01 predicted from fixtures, now
confirmed at scale. Also found: `methodFullName` MIS-RESOLUTION
(`router.get` -> `ctx:cookies:<returnValue>:<member>(cookies):get`), so mfn
must not be trusted without receiver-type corroboration.

**FALSE ORIGINS: 0 in both corpora.** Corpus B abstained completely rather
than guessing -- the desired failure mode.

```text
PROMOTION_JUSTIFIED: NO. Gates 2-7 MET (100% precision, 0 false origins,
no name dependence, families distinguishable, bounded causes). Gate 1
(>=2 mechanisms survive real code) NOT MET -- annotation survives,
registration does not. Honest state:
  NESTJS_ANNOTATION_PROVENANCE_SUPPORTED
  EXPRESS_SAME_MODULE_REGISTRATION_PROVENANCE_SUPPORTED
  GENERAL_REGISTRATION_PROVENANCE_NOT_YET_SUPPORTED
```

DOMINANT RESIDUAL: cross-module framework-object type propagation. Nominated
next: **JS-PROV-R03 — Cross-Module Framework-Identity Propagation
Characterization** (can identity propagate via import graph / exports /
argument-to-parameter binding, or is it a FRONTEND_GAP?). Acceptance anchor
exists: Corpus B's 14 registrations must gain identity with NO name heuristic
while Corpus A stays unchanged.

**Architecture preserved:** R01's finding holds under production validation --
there is NO single universal "web handler" proof mechanism. Annotation
provenance was completely UNAFFECTED by the cross-module structure that
destroyed registration provenance, because decorators attach to the
declaration rather than being inferred from a receiver type. Keep
`provenance_mechanism in {REGISTRATION, ANNOTATION}` as a first-class
discriminator; do not flatten.

## JS-PROV-R03 — cross-module framework-identity propagation characterization (no implementation)
Diagnoses JS-PROV-R02's single dominant residual. Full report:
`docs/corpus-scans/js-prov-r03/JS_PROV_R03_CHARACTERIZATION.md`.

**Result: NOT a frontend gap. Every required fact exists; exactly ONE hop is
missing.**

```text
LINK 1 constructor identity (defining module):  PRESENT  LOCAL router type=@koa/router
LINK 2 argument type at call site:              PRESENT  arg1 router type=@koa/router (12/12)
LINK 3 call edge caller->callee:                RESOLVED exact method fullNames
LINK 4 callee parameter type:                   ANY   <-- THE MISSING HOP
```

R02 observed `router: ANY` INSIDE the receiving module and concluded the type
"does not survive" module boundaries. R03 shows that in the DEFINING module it
is `@koa/router`, the argument carries it at every call site, and
`cpg.call.callee` resolves each cross-module `register(...)` to the exact
target -- the import/export wiring IS fully traversed. Only the
argument->parameter type binding across the already-resolved edge is absent.
Note `param0` (`this`) DOES carry a type and hints, so the parameter-typing
machinery works; it just is not fed by cross-module argument types.

Derivable from already-exported facts (arg type + `candidate_target_ids` +
parameter index). **Deliberately NOT implemented.** Four unmeasured questions
first: (1) conflicting argument types across multiple call sites need a join,
not last-writer-wins; (2) transitive propagation raises fixpoint/termination
concerns; (3) a propagated type is WEAKER evidence than a declared one and
needs its own resolution value (ANY-is-not-a-domain invariant); (4) the fix
may belong upstream in jssrc2cpg rather than in Fable -- an architectural
decision R03 does not settle.

**Independently unresolved:** even with this hop closed, Corpus B handlers read
`ctx.validatedData.*` (a MIDDLEWARE-WRITTEN property), so origin families would
still be wrong for most of that corpus. Two separate problems. Also, the R02
`methodFullName` mis-resolution remains unexplained -- mfn cannot be trusted
as framework evidence without receiver corroboration.

Acceptance anchor unchanged: Corpus B's 14 registrations must gain identity
with NO name heuristic while Corpus A stays EXACTLY unchanged (33 recognized,
16/6/12/0) and false origins stay 0 in both.

Nominated next: **JS-PROV-R04 — Argument->Parameter Type Propagation
Characterization** (measure conflict frequency; test transitivity/termination;
define the propagated-vs-declared resolution value; decide frontend-vs-Fable
ownership). PROMOTION_JUSTIFIED: NO (unchanged -- Gate 1 still unmet).

## JS-PROV-R04 — argument->parameter type propagation characterization (no implementation)
Determines the narrowest sound propagation rule and its JOIN semantics, over
10 adversarial teeth. Full report:
`docs/corpus-scans/js-prov-r04/JS_PROV_R04_CHARACTERIZATION.md`.

**Join semantics (the load-bearing result): a SET of observed types plus an
explicit `unconstrained_callsite` flag** -- NOT last-wins, NOT a collapsed
supertype. Conflicts are genuinely observable (`{Router, Db}`). Concrete + ANY
must NOT reduce to the concrete type: `ANY` means the domain is unconstrained
(R11 invariant). A collapsed supertype would discard exactly what R11/R12
consumers need.

Other measured results: positional mapping EXACT (implicit `this` at index 0
on BOTH sides, no offset, no crossover); declared types preserved for free by
gating on `param type == ANY`; recursion (direct + mutual) TERMINATES under
set-union -- a direct argument FOR sets over substitution; transitive case is
monotonic over a finite lattice so a fixpoint terminates; ambiguous callees
mechanically excludable via `|callee| == 1`.

**Two new hazards found, both only via the teeth (not the Corpus-B replay):**
- **Type-identity normalization missing**: `Router:<init>` (from `new Router()`)
  vs `Router` (from a declared return) are the same concept with DIFFERENT
  spellings -- a naive join would manufacture false conflicts.
- **REST parameters must be explicitly excluded**: argument index maps to an
  array ELEMENT, not the parameter. The ANY-gate abstains only incidentally.
- TS `any` and `unknown` both export as `ANY`, indistinguishable.

**CORPUS-B REPLAY: 12/12 confirmed** all yield `{@koa/router}`, singleton, all
preconditions met -- but this is the EASY shape (one callsite per parameter)
and does NOT exercise join semantics at all.

ARCHITECTURAL HOME: **B, Fable's neutral normalization layer.** Decisive
criterion is evidence preservation, not convenience: option A (upstream) as
normally implemented would overwrite `parameter.typeFullName`, making
propagated evidence INDISTINGUISHABLE from declared contracts -- the exact
R11 conflation. Option C re-fragments a general capability.

```text
PROMOTION_READY: NO. DOMINANT GAP: type-recovery RELIABILITY, not propagation
mechanics. TWO independent mis-resolutions now on record (R02 `router.get` ->
`ctx:cookies:...:get`; R04 spurious `prop:ts::program:Base` with a MALFORMED
separator on a value that never touches Base). Propagation is an AMPLIFIER --
building it before measuring the signal's error rate is the wrong order.
```

Nominated next: **JS-PROV-R05 — Type-Recovery Reliability Characterization**
(measure malformed/wrong-type frequency on the existing real corpora BEFORE
building anything transitive). Separation preserved: `router` param type is an
interprocedural TYPE-EVIDENCE problem; `ctx.validatedData.*` is a
middleware-derived PROVENANCE problem. Closing the first must not be reported
as closing the second.

### JS-PROV-R04 addendum — Q3 second sub-case closed
The first R04 pass omitted the prompt's second Q3 test
(`g(x: ConcreteA); g(concreteB as any)`). Closed in a follow-up; evidence in
`js-prov-r04/evidence/q3b_cast_erasure_results.txt`.

The ANY-gate abstains correctly (declared `ConcreteA` is not `ANY`), so the
stronger contract is preserved with no special case. **But the finding is what
propagation CANNOT see:** the value actually reaching `g` is a `ConcreteB` --
a real contract violation -- and the `as any` cast ERASED the argument type at
the callsite, so propagation observes only `ANY`. **Propagation is blind
precisely where a declared contract is being violated**, which is the exact
situation R11/R12 flagged as security-relevant. Bounds the capability: it
strengthens evidence about well-typed callsites and contributes nothing on
deliberately erased ones. Also re-confirms the normalization finding
(`ConcreteA` vs `ConcreteA:<init>` on the same type in the same file).

## JS-PROV-R05 — type-recovery reliability characterization (no implementation)
Asks the prior question to R04: when is Joern's recovered type evidence
trustworthy enough to consume at all? Full report:
`docs/corpus-scans/js-prov-r05/JS_PROV_R05_CHARACTERIZATION.md`.

**HEADLINE: type recovery produces a demonstrably WRONG type on a mainstream
pattern.** With `import { Router as R } from './mod/other'` alongside a
same-named LOCAL `class Router`, the imported instance's `typeFullName`
reports `main.ts::program:Router` -- the LOCAL class. Both TYPE_DECLs exist
and are correct/distinct (ids ...555 and ...570); the identifier->type binding
mis-resolves by short name. Not imprecision (`ANY`) -- a confident, specific,
INCORRECT answer. This is the THIRD independent type-recovery defect on record
(R02 `router.get`->`ctx:cookies:...:get`; R04 malformed `prop:ts::program:Base`,
which REPRODUCES here as `main:ts::program:Router`, confirming it systematic).

Other measured results: TYPE_DECL gives a structural id (+filename) but each
type ALSO has a duplicate EXTERNAL stub decl, and collapsing stub->real can
only be done by name -- circular with the R05-2 defect. `FRONTEND_RECOVERED`
is INDISTINGUISHABLE from `DECLARED` (the CPG records no provenance for how a
typeFullName arose), so `DECLARED > RECOVERED` cannot be asserted. All cast
forms (`as any`/`as unknown`/incompatible) collapse to ANY and are mutually
indistinguishable; only `<operator>.cast` in hints survives as a marker. HINTS
ARE AGGREGATED PER IDENTIFIER, NOT PER SITE (polluted across use sites).
Unions COLLAPSE to ANY at the parameter. Generics: parameter is literally `T`.
Type aliases get their own decl and do NOT resolve to the underlying type.

**Structural interfaces weaken JS-PROV-R01's negative control:** an object
literal satisfying an interface reports the interface type IDENTICALLY to a
nominal implementer. R01's `notFramework` discriminator passed only because
that fixture used an inline object-literal type; against a DECLARED interface
it would be weaker than measured.

```text
PROMOTION_READY: NO -- stronger case than R04. R04 blocked on "error rate
unmeasured"; R05 measured it and found a confirmed wrong type. Propagation
amplifies; amplifying a known-wrong signal is worse than not propagating.
DOMINANT GAP: frontend type-binding CORRECTNESS, not coverage.
```

Nominated next: **JS-PROV-R06 — Type-Binding Defect Characterization &
Upstream Disposition**: (a) measure short-name-collision + malformed-separator
frequency across the four existing real corpora to see if R05-2 is endemic or
a fixture artifact; (b) decide disposition -- these are jssrc2cpg defects, not
Fable modelling gaps, so an upstream bug report + version pin may be correct
rather than a Fable-side workaround. R04 placed the propagation LAYER in Fable;
R05 suggests its INPUTS may need fixing upstream.

## JS-PROV-R06 — frontend type-binding correctness audit (characterization + disposition)
Full report: `docs/corpus-scans/js-prov-r06/JS_PROV_R06_AUDIT.md`.
Permanent distinction adopted: `ANY` = weak evidence (safe to abstain on);
`WRONG CONCRETE TYPE` = actively dangerous (can fabricate provenance).

**BOTH expected findings REVERSED, and both reversals are recorded:**

1. **Wrong concrete types: 0 in real corpora.** 4 collision name-groups exist
   in fxa only (`Customs`x3, `DB`x2, `OtpRedisAdapter`x2, `ScopeSetLike`x2);
   0 in the other three corpora. `this` binds CORRECTLY (lexical); other
   collision-name params degrade to bare EXTERNAL STUBS = ambiguous, the SAFE
   failure mode. R05-2 requires import-alias + same-named local in ONE file --
   a pattern none of the four corpora contain. Honest statement: "real defect,
   NOT shown endemic," not "type recovery is broken."
2. **R01's discriminator UPHELD, but its STATED BASIS was WRONG.** R01 claimed
   "module-derived vs object-literal type shape" (fragile, as R05 warned).
   Part C shows it actually rests on the registration call's `methodFullName`
   (`express:express:<returnValue>:post`), independent of `typeFullName`. A
   class with a CONFIDENT concrete type (`FakeRouter`) implementing a DECLARED
   interface still yields `<unknownFullName>`. Result survives; R01's published
   reasoning is corrected here.

Quantified (fxa): identifiers 47,107 with **41% ANY**; parameters 8,372 with
**78% ANY**; malformed `typeFullName` = 0; malformed in
`dynamicTypeHintFullName` = 15 (real code, e.g.
`routes/utils/otp:ts::program:OtpUtils`) -- localizes that defect to hint
construction.

SAFE STRUCTURAL TYPE IDENTITY: **NO in general** (`referencedTypeDecl` fails on
aliases and resolves bare names to external stubs; no import-binding edge is
exposed). **YES for the one case JS-PROV needs**: framework provenance via
`methodFullName`, bypassing `typeFullName` entirely.

```text
DISPOSITION: VERSION_PIN_SUFFICIENT (Joern/jssrc2cpg 4.0.607, cpg 1.7.70),
with a minimal upstream report PREPARED (fixture/expected/actual/CPG state/why
wrong, no security-impact claim). NOT FABLE_CAN_CONTAIN -- containment would
need the same broken short-name logic, and no non-name-based check exists.
VERSION SENSITIVITY: UNDETERMINED (second ~1.7GB Joern install exceeded the
"cheap and controlled" condition; upgrading mid-milestone was disallowed).
PROPAGATION PROMOTION: NO.  PROVENANCE PROMOTION: NO -- but now for a WEAKER
reason: R01 is no longer disqualified by R05/R06; it remains blocked only by
JS-PROV-R02 Gate 1 (coverage, not correctness).
```

DOMINANT GAP INVERTED: type EVIDENCE SPARSITY, not incorrectness. The audit
went looking for false precision and found overwhelming ABSENCE (78% of real
parameters are ANY). Propagating from a 78%-ANY base yields little, and R04
already forbade reducing ANY to a concrete type.

Nominated next: **JS-PROV-R07 — Registration-Provenance Cross-Module Recovery**
(characterization). Since Part C/D proved `methodFullName` carries framework
provenance WITHOUT the defective type path, characterize whether JS-PROV-R02's
failed Koa registration sites can be recovered via callee/methodFullName
evidence -- closing Gate 1 without type propagation at all.

## JS-PROV-R07 — resolved-callee framework registration characterization (no implementation)
Tested whether registration identity can be proven from the resolved callee
even when the receiver is ANY. Full report:
`docs/corpus-scans/js-prov-r07/JS_PROV_R07_CHARACTERIZATION.md`.

**ANSWER: NO — and the failure mode is worse than absence.**

Corpus B, all 14 registrations have `RECV type=ANY`:
```text
post/put/delete (7):  mfn=<unknownFullName>                        callee=[] n=0
get             (5):  mfn=ctx:cookies:<returnValue>:<member>(cookies):get
                      callee=n=1 -> THE SAME WRONG METHOD
```
**Level 2 and Level 3 do NOT disagree -- they AGREE on a wrong answer.** A
"trust the resolved callee over methodFullName" rule would confidently register
Koa's COOKIE JAR accessor as the framework method for 5/14 routes.
Cross-checking the two levels gives NO protection; the error is upstream of
both. (populated-but-wrong: 5/14; no-evidence: 7/14; contradictions: 0.)

Adversarial teeth isolate the variable exactly: typed receiver -> both levels
100% correct (`/t1`,`/t7` anonymous cb,`/t8` middleware all give
`@koa/router:get|post`). ANY receiver -> **`/t2` (REAL router via helper) and
`/t3` (FAKE router via helper) are BYTE-IDENTICAL** in every exported fact,
including the same 5 candidate callees in the same order -- and
`@koa/router:get` appears among the candidates for BOTH. Any rule accepting
"a framework method is among the candidates" WOULD produce a false
registration. That shape is present and is promotion-blocking. FALSE
REGISTRATIONS = 0 only VACUOUSLY (no rule produced matches).

```text
Q5 OUTCOME: RECEIVER_TYPE_REQUIRED
R02 GATE-1 CLOSED: NO (0/14, unchanged)
TYPE PROPAGATION STILL REQUIRED: YES -- R07's hypothesis REFUTED, so R04
returns to the critical path (while remaining useful elsewhere).
```

Also recorded: framework identity is only a methodFullName STRING PREFIX
(`@koa/router:`), NOT structural module identity -- not silently upgraded.
Corpus B uses FOUR distinct argument shapes, so a "last argument is handler"
rule would be wrong. Handler identity / context role NOT measured -- blocked
upstream; measuring them on unestablishable registrations would be meaningless.

**R06's architectural principle REFINED:** "prefer direct program identity over
inferred type identity" -- *but a resolved call edge is only as good as the
receiver typing that produced it.* In a dynamically-dispatched language
"resolved callee" is NOT a direct program relation; it is itself an inference
from the receiver type. When that type is ANY the edge may be CONFIDENTLY
WRONG. `ctx.cookies.get` is the proof: it looks exactly like the direct
relation R06 recommended trusting, and it is fabricated.

Nominated next: **JS-PROV-R08 — Receiver-Type Recovery Disposition.** R03/R04/
R07 now converge on ONE blocker with a known shape. Decide disposition rather
than characterize further: (a) implement R04's rule under R05's measured
safe-input constraints and re-run Corpus B + the decisive `/t2`-vs-`/t3`
control (t2 must gain @koa/router, t3 must NOT); or (b) file the ANY-receiver
mis-resolution upstream alongside R06's alias defect. Option (a) is justified
in a way it was not after R04, because R07 eliminated the alternative.

## JS-PROV-R08 — safe receiver-type propagation (IMPLEMENTED)
First implementation milestone in the JS-PROV line. `JS_PROV_R08=15/15`, real
Joern. Full report: `js-prov-r08/JS_PROV_R08_RESULT.md`.
Module: `frontends/javascript-typescript/joern-ts/js_prov_r08.py`.

**Open-world type-evidence lattice** (two independent axes, kept separate):
```text
{T} unconstrained=False  -> CLOSED_SINGLE  proof=True   <-- ONLY proof state
{T} unconstrained=True   -> OPEN_SINGLE    proof=False
{T,U} any                -> CONFLICT       proof=False
{}  unconstrained=True   -> NO_EVIDENCE    proof=False
```
Encodes "we observed Router" != "receiver is provably Router". Per R11, ANY can
only OPEN the world, never contribute a member. All four states produced and
separately asserted.

**DECISIVE GATE SEPARATED:** `/t2` (real router via helper) observes
`['@koa/router']` CLOSED_SINGLE proof=True; `/t3` (fake via helper) observes
`['gate.js::program:FakeRouter']` -- EXCLUDES @koa/router, fabricates nothing.
R07 proved this pair byte-identical under ANY receivers (with `@koa/router:get`
among candidate callees for BOTH); separation comes entirely from receiver
evidence established BEFORE dispatch resolution. No candidate-callee-membership
rule exists.

**Two implementation defects found BY the fixture, not assumed away:**
1. The R05-2 short-name guard over-abstained: it counted R05's duplicate
   EXTERNAL STUB decls as collisions, so EVERY class-typed argument was
   skipped. `/t3` would have "passed" the gate by abstaining -- **green for the
   wrong reason**. Fixed to count non-external decls only.
2. Operator lowerings (`<operator>.assignment` etc.) emitted meaningless facts
   (one with 11 unrelated types). Excluded structurally.

Corpus-B replay: **14/14 router params recover `@koa/router` as CLOSED_SINGLE**
-- the receiver evidence R03 found missing and R07 proved unroutable-around.

Architecture invariants asserted: `declared_type` retained alongside and NEVER
overwritten; `parameter.typeFullName` never written; `resolution=
CALLSITE_PROPAGATED`; full derivation chain per fact. R07's registration logic
UNTOUCHED (hash-verified). Regressions: R02 28/28, R03 30/30, R07 31/31,
Gate24-TS 27/27, JSTS-R05 8/8. Wired into `run_all.py` (id 120).

**Honest limitations:** canonicalization is implemented but UNEXERCISED (no
`:<init>` spelling appeared as an argument type in fixture or Corpus B);
`NO_EVIDENCE` is never emitted; the narrowed R05-2 guard wasn't re-tested
against R05's own fixture; `unconstrained` is per-parameter, not per-path.

```text
R02 GATE-1 CLOSED: NOT YET -- deliberately not attempted. Wiring receiver
evidence into R07's registration path was OUT OF SCOPE by instruction.
PROMOTION_READY: YES for ObservedParameterTypeFact; NOT for
ExternalInputOriginFact (still needs the wiring step + the untouched
middleware-provenance problem, `ctx.validatedData.*`).
DOMINANT RESIDUAL: consumption, not production -- the evidence is sound and
nothing reads it yet.
```

Nominated next: **JS-PROV-R09 — Receiver-Evidence Consumption in Framework
Registration.** Strict rule: establish a registration ONLY from CLOSED_SINGLE
receiver evidence whose single observed type is a framework identity;
OPEN_SINGLE / CONFLICT / NO_EVIDENCE must all abstain. Re-run /t2-vs-/t3
end-to-end and Corpus B for Gate-1 closure; re-audit lookalikes for false
registrations.

## JS-PROV-R08 — receiver-type recovery disposition (IMPLEMENTATION)
First implementation milestone in the JS-PROV line. Full report:
`docs/corpus-scans/js-prov-r08/JS_PROV_R08_VERDICT.md`. JS-STATE untouched
(`js_state_r07.py` hash unchanged `b18bc7aa...`).

Disposition **(a)**: implement R04's rule under R05's safe-input constraints.
Option (b) upstream-only rejected -- R07 showed no alternative path exists, so
waiting on upstream would block the whole provenance line.

Implemented `frontends/javascript-typescript/joern-ts/observed_parameter_types.py`
-> **ObservedParameterTypeFact**. Records observational evidence in a SEPARATE
fact; NEVER mutates `parameter.typeFullName`. Wording per the R07 review: a
parameter receives *sufficient receiver-domain evidence under the R04/R05
rules*, NOT a proof of type -- `resolution = CALLSITE_PROPAGATED`, and
`declared_type` is carried alongside.

7 gates, all from prior measurements: G1 single resolved callee (R04 Q9);
G2 plain-identifier arg (R05: ctor calls -> BLOCK, casts -> ANY); G3 no
`<operator>.cast` hint (R05 Q8); G4 declared param type is ANY (R04 Q3);
G5 not variadic/rest (R04 Q5); G6 short-name not ambiguous (R05-2 defect
guard); **G7 NEW, from measurement** -- operator intrinsics excluded, found
because the first Corpus-B run emitted `<operator>.assignment` "facts" with
150+ observed types.

```text
DECISIVE CONTROL: JS_PROV_R08=12/12
  /t2 real router via helper  -> ['@koa/router'] established
  /t3 fake router via helper  -> @koa/router NOT gained
  (these were BYTE-IDENTICAL in exported facts under R07)
  conflicting callsites -> SET of both, never last-wins
  ANY contamination -> observes @koa/router but domain_established=FALSE
  cast / declared / rest -> ABSTAIN
```

**Corpus B (real): 14/14 register-lambda `router` params gain @koa/router**,
all established, all singleton sets. 80 facts total (47 established, 33
unconstrained). **G6 fired on REAL code** for `handler` and `validator` --
the R05-2 defect guarded in production, not just in a fixture.

**R02 Gate 1 NOT yet closed**: receiver evidence is restored, but the
registration layer must now consume it, and R07's constraint carries forward
(resolved-callee evidence usable ONLY because the receiver is now evidenced).
**`ctx.validatedData.*` remains untouched** -- a different provenance edge;
closing the type-evidence problem is NOT closing the middleware-provenance one.
Transitivity NOT implemented (single-pass; R04 Q7 showed a fixpoint would be
needed for deeper chains).

Nominated next: **JS-PROV-R09 — Registration Recognition over
ObservedParameterTypeFact.** Re-run R02's Corpus-B registration recognition
with receiver evidence available and re-test /t2-vs-/t3 END-TO-END at the
REGISTRATION level. Gate 1 closes only if /t3 still produces no registration.

## JS-PROV-R09 — registration recognition over ObservedParameterTypeFact (IMPLEMENTATION)
Full report: `docs/corpus-scans/js-prov-r09/JS_PROV_R09_VERDICT.md`. JS-STATE
untouched. `framework_registration.py` -> **FrameworkRegistrationFact**.

Identity comes ONLY from receiver-domain evidence (R08). `methodFullName` and
resolved-callee are deliberately UNUSED, per R07's measurement that they are
correlated error under an ANY receiver (5/14 Corpus-B `get` sites both pointed
at `ctx:cookies:...:get`). The call name only SELECTS the verb after the
receiver is established. Framework profile is explicit/curated policy
(`@koa/router`, `koa`, `express`); unrecognized module -> UNKNOWN, never
"not a framework".

**HEADLINE: jssrc2cpg mis-propagates receiver types, and recognition now
survives it.** The first fixture run gave ZERO registrations. Cause was an
assumption in the new module (skip receivers whose type isn't ANY) -- the
fixture's receivers were CONCRETE and WRONG: jssrc2cpg assigned
`t:ts::program:FakeRouter` (malformed `:ts::` separator, the R04/R05 defect) to
**4/4 router params INCLUDING the real `@koa/router` one**. Joern performs its
own argument->parameter propagation and got it confidently wrong. Fixed by not
trusting `recv_type` at all; disagreement is recorded
(`cpg_receiver_type_disagrees`) and gate-asserted. Had the assumption stood,
`installReal` would have been registered as a FakeRouter -- a fabricated
relationship of exactly the kind R06 warned about.

```text
DECISIVE CONTROL: JS_PROV_R09=11/11 (end-to-end at REGISTRATION level)
  installReal -> REGISTERED @koa/router, evidence=RECEIVER_DOMAIN_EVIDENCE
                 (cpg_recv=FakeRouter, DISAGREES=True)
  installFake -> ABSTAIN RECEIVER_NOT_A_PROFILED_FRAMEWORK      [GATE-1 condition]
  installBoth -> ABSTAIN RECEIVER_AMBIGUOUS_ACROSS_CALLSITES
  installAny  -> ABSTAIN RECEIVER_DOMAIN_NOT_ESTABLISHED (observes @koa/router
                 but one ANY callsite => domain not established, R11 invariant)
  exactly ONE registration in the fixture

CORPUS B: 14/14 established (was 0/14 at R02); by verb post 7/get 5/put 1/
delete 1 = EXACT ground-truth match; 0 false registrations. The 5 `get` sites
R07 found resolving to ctx.cookies.get are now registered from RECEIVER
evidence, never from that fabricated callee.
```

**R02 GATE-1 CLOSED: YES** -- annotation (NestJS) + registration (Koa) both
survive real code.

Still NOT established: handler identity + context-parameter role (now UNBLOCKED
but unmeasured; R07 recorded FOUR distinct argument shapes in Corpus B, so no
"last argument is handler" rule). `ctx.validatedData.*` UNTOUCHED -- where a
handler came from is not where the values inside it came from.
`ExternalInputOriginFact` still NOT promoted.

Nominated next: **JS-PROV-R10 — Handler Identity & Context-Parameter Role over
FrameworkRegistrationFact**, characterizing Corpus B's four argument shapes
rather than assuming a positional handler rule.

## JS-PROV-R10 — handler identity + context-parameter role characterization (no implementation)
Full report: `docs/corpus-scans/js-prov-r10/JS_PROV_R10_CHARACTERIZATION.md`.
`FrameworkRegistrationFact` (R09) is an INPUT, not rediscovered. No parameter
names used as evidence.

**Four Corpus-B argument shapes enumerated from production** (8/3/2/1),
matching R07's independently-derived count. arg0=receiver, arg1=route literal
in ALL shapes; callbacks are args >= 2, count 1..3.

```text
callback args 33 -> 21 ESTABLISHED (REF->METHOD), 12 UNKNOWN
  IDENTIFIER 23 -> 21 established, 2 unknown (lambda assigned to a local:
                   carries a function TYPE but no resolvable METHOD)
  CALL       10 ->  0 established: ALL WRAPPER-RETURNED (`validate(schema)`)
                   resolve to the WRAPPER MODULE, not the returned function.
                   Tell: generic `(p0,p1,p2)` stub signature.
parameter roles: 21 CONTEXT, 9 NEXT
```

**Name-independence PROVEN**: `(ctx,next)` / `(context,continuation)` /
`(banana,orange)` all yield identical CONTEXT/NEXT roles. Roles are positional
(param index 1 after implicit `this`). Controls: 2nd param NEVER gets CONTEXT
even when the body uses it; 0-param -> no role; 3rd param -> NO_ROLE (nothing
invented beyond framework arity). Named handler resolves
registration->callback->REF/METHOD->METHOD_PARAMETER with NO type propagation.
Middleware chain `post(path,mwA,mwB,h)`: ALL THREE established, Koa's
"every callback is middleware" semantics PRESERVED -- no MAIN_HANDLER invented.

**NEGATIVE CONTROL FAILURE (promotion-blocking, reported not tuned away):**
`router.get("/nc", 42 as any)` produced a FALSE ESTABLISHED with
`p1->CONTEXT, p2->NEXT`. The cast lowered to a CALL resolving to a generic
external stub -- the SAME `(p0,p1,p2)` tell as the wrapper case. Shared root
cause: **stub resolutions admitted as if they were real methods.** One
structural gate (resolved target must be a defined, non-external method) would
fix BOTH the false positive AND convert the 10 wrapper callbacks from
wrong-identity to honest abstention. Not implemented (characterization only).

Also found: **R09 scope boundary** -- `framework_registration.py` only handles
receivers that are PARAMETERS. A directly-registered local router yields zero
registrations. Corpus B is entirely parameter-shaped so R09 never exercised it.
Recorded, not patched.

**`validatedData` boundary PRESERVED**: reaching `parameter = KOA_CONTEXT` does
NOT establish an origin family. `ctx.validatedData.username` stays
`ORIGIN_FAMILY = UNKNOWN`. Notably the 10 unresolvable callbacks ARE the
`validate(...)` middlewares, so the code that populates `validatedData` is
currently opaque -- which strengthens the boundary.

```text
HANDLER LAYER PROMOTION_READY: NO (4/6 gate conditions met; fails on negative
controls remaining silent, and partially on unresolved identities abstaining)
EXTERNAL-INPUT ORIGIN PROMOTION_READY: NO
```

Nominated next: **JS-PROV-R11 — Middleware State Provenance**
(KOA_CONTEXT -> middleware writes -> ctx.validatedData -> handler reads). A
state-flow problem, not a recognition problem. The small stub-resolution gate
folds in as a prerequisite fix, not its own milestone.

## JS-PROV-R11 — middleware state provenance characterization (no implementation)
Full report: `docs/corpus-scans/js-prov-r11/JS_PROV_R11_CHARACTERIZATION.md`.

**CORRECTS R10:** wrapper-returned middleware identity IS recoverable —
`CALL -> callee METHOD -> RETURN -> METHOD_REF -> METHOD`. Confirmed in fixture
(`validate:<lambda>0`) AND in real Corpus B
(`middlewares/validate.middleware.js::program:validate:<lambda...>` writes
`ctx.validatedData = value`). R10 reported those 10 callbacks as unresolvable;
they were UNDER-resolved by one hop. `RETURNED_HANDLER_ESTABLISHED`.

**NEXT-BOUNDARY tooth ESTABLISHED structurally** via block child `order` (line
numbers were tried first and were useless — one-line bodies put the write and
`next()` on the same line):
```text
producer     nextOrder=2  WRITE order=1  BEFORE_NEXT
afterWriter  nextOrder=1  WRITE order=2  AFTER_NEXT   <- downstream CANNOT see it
condWriter   write nested in CONTROL_STRUCTURE  -> MAY vs MUST separable
```
Write-side origin families VISIBLE: `ctx.request.body` -> HTTP_BODY,
`ctx.query` -> HTTP_QUERY, literal -> no external origin,
`normalize(ctx.request.body)` -> DERIVED_FROM_HTTP_BODY (preserved as derived,
never claimed equivalent; no sanitization claim).

**Corpus-B finding that breaks the assumed story:** `ctx.validatedData` has
MULTIPLE WRITERS with DIFFERENT origins — `validate(schema)` creates it from
the request, then downstream *validators* write `ctx.validatedData.user = user`
from DATABASE lookups. 24 distinct read sites across handlers AND validators.
So a single origin family for `validatedData` would be WRONG; any join must be
PROPERTY-PATH granular, not object-level. This vindicates the boundary held
since R03 — mapping validatedData to HTTP_BODY on the strength of its name
would have been incorrect for a real subset of its own fields.

**NOT measured: the write->read JOIN itself.** All ingredients now exist
(registration R09, callback identity R10+Q1, context role R10, write facts with
relative_to_next, read facts, origin families) but the relation was not built,
so its decisive negative controls were NOT exercised: Q4 unrelated objects,
Q5 separate routes, Q6 ordering. NO state-flow counts are reported —
claiming flows established on un-exercised negatives is the exact failure mode
this line has been avoiding.

```text
STATE FLOWS ESTABLISHED/MAY: 0 / 0 (join not built)
MIDDLEWARE STATE LAYER PROMOTION_READY: NO
EXTERNAL INPUT ORIGIN PROMOTION_READY:  NO
```

Nominated next: **JS-PROV-R12 — Context State-Flow Join (implementation)**,
gated on two prerequisites landing first: (1) R10's stub gate (a callback target
must resolve to a defined, non-external METHOD — `42 as any` must stay UNKNOWN),
and (2) wrapper-return resolution from Q1. Acceptance teeth are exactly the
negatives R11 could not exercise: unrelated objects must not join, separate
routes must not join, `consumer,producer` order must not receive producer
state, and AFTER_NEXT writes must not reach downstream reads.

## JS-PROV-R12 — context state-flow join (IMPLEMENTATION)
`context_state_flow.py` -> **ContextStateFlowFact**.
Full report: `docs/corpus-scans/js-prov-r12/JS_PROV_R12_VERDICT.md`.
`context_state_flow.py`. JS-STATE untouched. Wired into run_all (id 122).

FROZEN INVARIANT (R11, source-confirmed): provenance is
`(context identity, property path, writer, origin family, strength, ordering)`
-- NEVER `ctx.validatedData -> HTTP_BODY`. Prefix semantics: a write establishes
a read iff writer_path is a path-PREFIX of reader_path.

```text
FIXTURE: JS_PROV_R12=14/14 -- all 8 specified negative controls load-bearing
  1 different object          never joins
  2 different route           /r1 and /r2 both write `shared`: NO cross-join,
                              and origins stay DISTINCT (HTTP_BODY vs HTTP_QUERY)
  3 AFTER_NEXT                establishes nothing; abstention recorded
  4 conditional               MAY, never MUST
  5 stub (42 as any)          establishes nothing; abstention recorded
  6 wrapper validate(schema)  JOINS via R11 RETURN->METHOD_REF hop
  7 siblings .user/.email     NO join
  8 parent/child              whole->.email and .user->.user.id = ANCESTOR_WRITE
  + reader positioned BEFORE writer establishes nothing
```
Control 6 initially FAILED -- R11's wrapper hop was declared a prerequisite but
not wired. Fixed in the callback export
(`CALL -> callee METHOD -> RETURN -> METHOD_REF -> METHOD`), NOT by relaxing
the gate.

**CORPUS B: 0 flows.** Cause located precisely, and it is NOT the state export
-- that works on real code:
`validate:<lambda>1 WRITE validatedData ord=3 nextord=4` (BEFORE_NEXT, correct).
The break is CALLBACK RESOLUTION one layer up: Corpus B reaches the wrapper via
CommonJS `module.exports = validate` + `require(...)`, so `validate(schema)`
resolves to the MODULE (18x) not the `validate` METHOD -- no RETURN to follow,
and the module's generic `(p0,p1,p2)` stub signature then correctly trips the
stub gate. The 10 `WRITE_NO_NEXT` abstentions are the second-position
`validator` functions, unreachable because the chain broke at callback 1.

**Same shape for the THIRD time**: R03 (receiver type across modules), R10/R11
(wrapper-return one hop short), now callee identity across `module.exports`.
Cross-module identity -- not analysis sophistication -- remains the binding
constraint on this line.

```text
MIDDLEWARE STATE LAYER PROMOTION_READY: NO (sound on controlled input, ZERO
real-code flows -- reporting 14/14 as success would be the exact failure mode
this line has avoided)
EXTERNAL INPUT ORIGIN PROMOTION_READY:  NO
```

Nominated next: **JS-PROV-R13 — Cross-Module Export Identity.** Recover
`require(m)` / `module.exports = fn` so a call to an imported function resolves
to the METHOD not the module object. Acceptance anchor is unambiguous and
already exists: Corpus B's 10 `validate(schema)` callbacks must resolve to
`validate:<lambda>1`, and the R12 fixture must stay 14/14.

### JS-PROV-R12 addendum — R12-1 returned-function identity promoted
Extracted the higher-order traversal from the callback export into a standalone,
framework-NEUTRAL primitive: `returned_function_identity.{sc,py}` ->
`ReturnedFunctionIdentityFact` (`CALL -> callee METHOD -> RETURN -> METHOD_REF
-> returned METHOD`). Reusable by callback registration, event handlers,
decorators, other frameworks' middleware. `JS_PROV_R12` still 14/14.

**Caveat recorded, NOT exploited:** run on Corpus B it emits a MODULE-level fact
(`middlewares/validate.middleware.js::program -> validate:<lambda>1`) that
happens to bridge exactly R12's failing gap. It is an artifact of `m.ast.isReturn`
walking all AST DESCENDANTS -- the module program node inherits the nested
`validate` function's RETURN. That is AST containment, NOT export semantics: a
module with TWO returning functions would map to both, ambiguously, with no
evidence about what `module.exports` actually exports. Using it to close R12's
gap would be joining on an accident of AST nesting. **R13 still needs real
export identity.** Treated as a hint-to-verify, never a resolution.

## JS-PROV-R13 — export identity resolution (characterization)
Full report: `docs/corpus-scans/js-prov-r13/JS_PROV_R13_CHARACTERIZATION.md`.

**Prerequisite landed:** `ReturnedFunctionIdentityFact` contract FROZEN to
DIRECTLY-returned (`_.method.fullName == m.fullName`), excluding nested-method
RETURNs. The Corpus-B module-level containment artifact is gone AT SOURCE, not
filtered downstream. R12 still 14/14.

**Export side STRONG — decisive negative PASSES.** `m1.js` declares BOTH
`validate` and `other` (each returning a different lambda) and exports only
`other`; the export assignment resolves RHS to `m1.js::program:other`, so
`validate` is unreachable through it. `exports.X = fn` and
`module.exports.X = fn` preserve named-member identity.
`module.exports = {a,b}` is PARTIAL (RHS is a BLOCK; member traversal unmeasured).

**Consumer side WEAK and FABRICATING.** `require('./mN')` -> typeFullName=ANY
for all modules. Worse: `m2.validate(1)`, `m3.validate(1)`, `m4.validate(1)` ALL
resolve to `app.js::program:validate` -- **a function that does not exist in
app.js** -- collapsing three different modules' three different lambdas onto one
fabricated identity. FOURTH independent confidently-wrong resolution on record
(R02 router.get, R05-2 import alias, R09 receiver type, now callee across
require).

4 of 5 chain links exist; the missing one is
`module specifier -> file -> export assignment`. Raw material IS structural
(require literal `'./m1'` + export `filename=m1.js`), but any implementation
must OVERRIDE the fabricated callee, never consult it.

```text
EXPORT IDENTITY PROMOTION_READY: NO
```

Nominated next: **JS-PROV-R14 — Module Specifier Resolution (implementation)**.
Anchors already exist: (1) m1 -> `other`, NEVER `validate`; (2) m2/m3/m4 each
resolve to their OWN module's validate, never collapsing; (3) Corpus B's 10
`validate(schema)` callbacks reach `validate:<lambda>1`; (4) R12 stays 14/14.

**Thesis principle (second instance):** *AST containment is not symbol identity.*
Same lesson as R07's derived call edges from another direction -- R07's callee
inherited a bad receiver type, R12's module node inherited a nested RETURN, and
here require-crossing calls inherit a fabricated same-file callee. Each time the
graph offered a confident answer no program relation supported.

## JS-PROV-R14 — module specifier resolution (IMPLEMENTATION)
`module_export_identity.sc` + `module_specifier_resolution.py` ->
**ModuleExportIdentityFact**. Report: `docs/corpus-scans/js-prov-r14/`.
Wired into run_all (id 123). **JS_PROV_R14=9/9.** Regressions: R07 31/31,
R08 12/12, R09 11/11, R12 14/14.

Closes R13's missing link. `identity_evidence = REQUIRE_BINDING+EXPORT_ASSIGNMENT`
ONLY -- the frontend's callee is OVERRIDDEN, never consulted, because R13
measured it resolving m2/m3/m4's `.validate(1)` all to
`app.js::program:validate`, a function that does not exist.

```text
m1(1)          -> m1.js <default> -> :other   -> other:<lambda>1   (DECISIVE NEGATIVE)
m2.validate(1) -> m2.js validate  -> distinct identity
m4.validate(1) -> m4.js validate  -> distinct identity
m3.validate(1) -> ABSTAIN (object-literal export: member not exposed at BLOCK)
```
m1 declares BOTH validate and other, exports only `other` -- resolves to `other`
and OTHER's lambda; `validate` unreachable. m2/m4 do NOT collapse.

**Corpus B: 45 facts, 9 `validate(schema)` callsites now reach
`validate:<lambda>1`** -- the exact target R12 could not reach. Rule added FROM
MEASUREMENT: the first run resolved 0 (all 176 non-relative specifiers abstained
as external). Corpus B uses `app-module-path`, so non-relative specifiers are now
ALSO tried project-root-relative -- still a PATH relation, conditional on a real
file with a real export assignment existing there, so genuine external packages
still abstain. Fixture anchors unchanged.

**Corpus-B state flows remain 0 and are NOT claimed as closed** -- R14 resolves
identity but is not yet wired into `callback_args`, so R12's join still receives
the module.

Nominated next: **JS-PROV-R15 — wire export identity into callback resolution**,
then re-run the R12 join. Acceptance: R12 stays 14/14, R14 stays 9/9, and Corpus
B yields PER-PROPERTY flows (validatedData.email -> HTTP_BODY distinct from
validatedData.user -> DB_LOOKUP).

## JS-PROV-R15 — module export identity consumed in callback resolution (IMPLEMENTATION)
Report: `docs/corpus-scans/js-prov-r15/`. `context_state_flow.py` now consumes
`ModuleExportIdentityFact` via EXACT call-id match (never filename/name
broadening), preferring explicit export identity over frontend callee inference.

```text
R12 fixture 14/14 unchanged | R14 fixture 9/9 unchanged
CORPUS B STATE FLOWS: 23 (was 0), all MUST, all MODULE_EXPORT_IDENTITY
```
The full chain now runs on real code: require specifier -> file -> export
assignment -> exported method -> returned lambda -> callback identity ->
context write -> BEFORE_NEXT ordering -> property-prefix join -> downstream read.

**10-vs-9 accounted for:** R10's 10 wrapper-returned callbacks = 9
`validate(schema)` (RESOLVED) + 1 `uploadMiddleware.single('file')`
(UNRESOLVED). `upload-file.middleware.js` does
`module.exports = multer({ storage })` -- the exported value is the RETURN OF A
THIRD-PARTY FACTORY CALL, not an identifier naming a declared function, so there
is no exported METHOD to resolve. Classified `EXPORT_RHS_IS_RUNTIME_CALL`, a
genuine model boundary. Coverage 9/10, tenth accounted for.

**PER-PROPERTY PAYOFF NOT ACHIEVED ON CORPUS B — reported honestly.** All 23
flows carry `origin_family=UNKNOWN`. The write is
`ctx.validatedData = value` where `value` is DESTRUCTURED from
`await schema.validate({...ctx.request.body, ...ctx.query}, ...)` -- three
unmodelled hops (object spread, third-party call, destructuring). The classifier
correctly abstains rather than guessing HTTP_BODY; guessing would have been
wrong twice over, since the value merges body AND query. The per-property
distinction is demonstrated on the FIXTURE only.

```text
IDENTITY half (R03-R15): CLOSED
ORIGIN half:             OPEN -- ExternalInputOriginFact still NOT promotable
```

Nominated next: **JS-PROV-R16 — Write-RHS Origin Dataflow** (narrow: can
`ctx.X = value` from `{...ctx.request.body, ...ctx.query}` be established as
DERIVED_FROM_{HTTP_BODY,HTTP_QUERY} as a SET, per R04 join semantics, without
claiming equivalence through the third-party call?).

## JS-PROV-R16 — write-RHS origin dataflow characterization (no implementation)
Report: `docs/corpus-scans/js-prov-r16/`. Three sub-questions kept SEPARATE.

**Q1 SPREAD COMPOSITION: REPRESENTABLE.** `<operator>.spread` is a distinct node
and a multi-spread literal keeps BOTH sources as separate children:
`{...ctx.request.body, ...ctx.query}` -> `{HTTP_BODY, HTTP_QUERY}` as a SET
(R04 join semantics, never collapsed). Literal members contribute nothing (T4);
non-HTTP spread yields no HTTP origin (T5). CAVEAT: the spread's first argument
is the ACCUMULATOR TEMP (`_tmp_2`) -- a rule must read the source operand or
every spread appears to derive from a temp.

**Q2 OPAQUE THIRD-PARTY CALL: abstention is FORCED, not chosen.**
`schema.validate(a3)` -> `methodFullName=<unknownFullName>`, **0 callees** (joi
is not in sources). Correct label `ORIGIN_TRANSFORMED_BY_UNMODELLED_CALL`,
carrying `transform_input_origins` as evidence. **T9 (value-preserving wrapper)
deliberately NOT distinguished from T8** -- that needs a third-party
value-preservation model, not built.

**Q3 DESTRUCTURING: MEMBER-PRECISE, not a barrier.** `const {value} = r` lowers
to `_tmp_5 = r; value = _tmp_5.value`. `.value` and `.error` separable ->
compatible with R12 prefix semantics.

**CORPUS-B DIAGNOSIS: R15's `origin_family=UNKNOWN` is CONFIRMED CORRECT.** The
chain is exactly T3 -> T8 -> T6; composition and destructuring are recoverable,
the Joi call between them is not. Best sound claim:
`ctx.validatedData <- ORIGIN_TRANSFORMED_BY_UNMODELLED_CALL` with
`transform_input_origins = {HTTP_BODY, HTTP_QUERY}` -- strictly more than
UNKNOWN, strictly less than DERIVED_FROM_HTTP_BODY.

Nominated next: **JS-PROV-R17 — Transform-Input Origin Fact** (narrow
implementation). Acceptance: R12 14/14 and R14 9/9 unchanged; Corpus B reports
{HTTP_BODY,HTTP_QUERY} as transform INPUTS while origin_family stays UNKNOWN;
T5 contributes no HTTP origin; T8 and T9 both abstain.

## JS-PROV-R17 — transform-input origin fact (IMPLEMENTATION)
Report: `docs/corpus-scans/js-prov-r17/`. `local_definitions.sc` +
`transform_input_origin.py`. **JS_PROV_R17=12/12**; R12 14/14, R14 9/9 unchanged.
Wired into run_all (id 124).

FROZEN three-way distinction, gate-enforced against collapse in EITHER direction:
`DERIVED_FROM_*` (output established) / `TRANSFORM_INPUT {..}` (origins entered,
output NOT established) / `UNKNOWN` (no evidence). Set-valued and open-world
(`unconstrained_input`), per R04.

```text
a1 {...body}->HTTP_BODY est | a2 {...query}->HTTP_QUERY | a3 both -> SET
a4 {k:1,...body}->HTTP_BODY (literal dilutes nothing) | a5 {...other}-> invents nothing
value/error -> UNKNOWN + TRANSFORM_INPUT{BODY,QUERY}, NOT established
p (value-preserving wrapper) -> NOT distinguished from opaque; both abstain
```

**SOUNDNESS BUG found and fixed mid-implementation.** Unwrapping `await` (needed
so transforms behind it stay visible) caused spreads nested inside a CALL's
ARGUMENTS to be harvested as the call's own result -- Corpus B briefly reported
`ctx.validatedData -> MULTIPLE, output_origin_established=TRUE`, manufacturing
established provenance THROUGH the unmodelled Joi call. Fixed by guarding spread
harvesting to RHS that is itself an object literal. **It failed in the UNSAFE
direction and was caught only by re-checking Corpus B after the change** --
fixture-only verification would have shipped it.

**CORPUS B partially achieved:** transform boundary CORRECT (UNKNOWN /
UNMODELLED_CALL / not established), but `transform_input_origins=[]` with
`unconstrained_input=true`. Cause: Corpus B passes an INLINE OBJECT LITERAL
(`schema.validate({...ctx.request.body, ...ctx.query}, {...})`) whereas the
fixture passes a named local (`a3`); `local_defs` resolves arguments by named
local only. A representational gap yielding a correct conservative abstention,
not an unsoundness.

Nominated next: **JS-PROV-R18 — Inline Expression Argument Resolution** (give
inline object-literal/expression arguments a resolvable identity by node id
rather than code string). Acceptance: Corpus B `ctx.validatedData` reports
transform_input_origins {HTTP_BODY,HTTP_QUERY} while origin_family STAYS UNKNOWN
and output_origin_established STAYS false; R17 12/12, R12 14/14, R14 9/9.

## JS-PROV-R18 — inline expression argument resolution (IMPLEMENTATION)
Report: `docs/corpus-scans/js-prov-r18/`. **JS_PROV_R17=18/18** (R17's 12 +
R18's 6 node-identity teeth); R12 14/14, R14 9/9 unchanged.

**ArgumentValueRef** = `LOCAL:<name>` | `EXPRESSION_NODE:<node-id>` -- keyed by
NODE IDENTITY, never a code string (code strings are not identities).
Expression-general by design; object literals are just the first supported form,
with no `inline_object_literal` side channel.

**The nested-call control FAILED on first run** -- `opaque(inner({...body}))`
harvested HTTP_BODY for the OUTER call, attributing an inner transform's inputs
to the outer one (same unsafe direction as R17's bug). Fixed structurally: only
an argument that IS ITSELF an object literal contributes spread sources; a CALL
argument is a nested transform contributing nothing. These are now separated:
`opaque({...body})` -> transform input BODY, vs
`const out = opaque({...body})` -> out.origin NEVER HTTP_BODY.

All R18 teeth pass: inline both-spreads -> both inputs; literal-only -> none;
unrelated spread -> nothing invented; two identical inline objects at different
callsites stay DISTINCT by node id; opaque gate intact.

```text
CORPUS B PROMOTION CONDITION MET on real code:
  ctx.validatedData
    origin_family             = UNKNOWN
    transform_input_origins   = {HTTP_BODY, HTTP_QUERY}
    transform                 = UNMODELLED_CALL
    output_origin_established = false
```
Fable can now report: *this state value passed through an unmodelled transform
whose known external inputs include the HTTP body and query string; the output's
provenance itself is not established.*

`TransformInputOriginFact` PROMOTION_READY. `ExternalInputOriginFact` still NO
(output origin remains unestablished -- correctly, absent third-party semantics).

Nominated next: **JS-PROV-R19 — carry transform-input evidence through R12's
state-flow join**, so downstream reads (`ctx.validatedData.email`) inherit
`transform_input_origins` WITHOUT upgrading `origin_family`. Acceptance:
property-granular propagation on Corpus B; origin_family stays UNKNOWN and
output_origin_established stays false at every reader; all gates unchanged.

## JS-PROV-R19 — transform-input evidence transport (IMPLEMENTATION; see addendum below)
Report: `docs/corpus-scans/js-prov-r19/`. **JS_PROV_R12=20/20** (R12's 14 +
R19's 6 propagation teeth); R14 9/9, R17 18/18 unchanged.

R12's join now attaches R17/R18 origin evidence to every flow, computed on the
WRITER's RHS and carried to the reader UNCHANGED (`origin_family`,
`transform_input_origins`, `transform`, `output_origin_established`,
`unconstrained_input`). Context parameter taken POSITIONALLY (index 1), per R10.

**Invariant `carried != upgraded`, gate-enforced in three directions:** no flow
claims output established without an established writer origin; a transform-fed
flow never reports a DERIVED origin_family; transform-fed flows never set
output_origin_established.

```text
CORPUS B — property-granular propagation, no upgrade:
  read validatedData        origin=UNKNOWN tin={HTTP_BODY,HTTP_QUERY} est=false
  read validatedData.email  origin=UNKNOWN tin={HTTP_BODY,HTTP_QUERY} est=false
  read validatedData.token  origin=UNKNOWN tin={HTTP_BODY,HTTP_QUERY} est=false
  (23 flows, all UNMODELLED_CALL, all not established)
```
The fixture simultaneously proves the other direction survives: established
writes still propagate a real origin_family, and two routes writing the SAME
property path keep DISTINCT origins (HTTP_BODY vs HTTP_QUERY). Carrying
evidence flattened nothing.

`TransformInputOriginFact` + state-flow carriage PROMOTION_READY.
`ExternalInputOriginFact` still NO -- output provenance across Joi is not
established and will not be, absent a third-party semantics layer.

**Chain R03->R19 complete for its stated scope.** Optional next, by
evidence-value: (a) second real corpus for the WHOLE chain (the R02 lesson: one
corpus is not generalization); (b) curated value-preservation profile for
joi/zod/yup, converting TRANSFORM_INPUT -> DERIVED_FROM_* only where explicitly
characterized; (c) the NestJS annotation path, where `@Body()` names the origin
family directly with no transform in the way.

### JS-PROV-R19 addendum — spec gaps closed
The first R19 pass under-built the spec in three ways, all now closed.
**JS_PROV_R12=28/28**; R07 31/31, R08 12/12, R09 11/11, R14 9/9, R17 18/18.

1. **Two axes now EXPLICIT**: `state_flow_strength` (MUST|MAY|UNKNOWN) and
   `origin_strength` (ESTABLISHED|TRANSFORM_INPUT_ONLY|UNKNOWN) are fields on
   every flow, not implied by `resolution` + a boolean. Gate-enforced: a MUST
   edge never upgrades TRANSFORM_INPUT_ONLY to ESTABLISHED.
2. **WRITER PRECEDENCE implemented (was MISSING).** R12 emitted a flow for
   EVERY prefix-matching writer, so a `.user` read still inherited the
   whole-object writer -- exactly what the critical overwrite tooth forbids.
   Now the most-specific writer is `effective`; broader ones are RETAINED and
   marked `shadowed_by_more_specific_writer` (inspectable, not dropped).
3. **Overwrite tooth added and passing** on a new `/ov` fixture route:
```text
read validatedData.user   writer=ovNarrow spec=2 effective=TRUE  origin=ESTABLISHED
read validatedData.user   writer=ovBroad  spec=1 effective=FALSE (shadowed)
read validatedData.email  writer=ovBroad  spec=1 effective=TRUE  TRANSFORM_INPUT_ONLY{BODY,QUERY}
```

CORPUS B: 23 effective flows, ALL `MUST` + `TRANSFORM_INPUT_ONLY`,
`origin_family=UNKNOWN`, `est=false`, tin={HTTP_BODY,HTTP_QUERY} at
`validatedData`, `.email`, `.token`. **`ctx.validatedData.user` has NO effective
read in Corpus B** -- the `.user` writes live in validator middlewares whose
readers are not reached (they stay in the WRITE_NO_NEXT /
WRITER_IDENTITY_UNKNOWN_OR_STUB abstentions). So the mixed-origin container case
is FIXTURE-ONLY on real code; claiming otherwise would overclaim.

Frozen rule extended: *nested transforms do not donate inputs to an outer
transform* -- and one level up, *a broader writer does not donate evidence to a
read a more specific writer already governs.*

NOTE: the first pass shipped WITHOUT the overwrite tooth; transport worked and
Corpus B looked correct, and the gap was invisible until the spec was re-read
against the implementation. Fourth would-have-overclaimed defect in this line,
and the first found by re-reading rather than a predeclared test.

## PROMOTION GATE FORMALIZED (post-R19)
`docs/PROMOTION_GATE.md` + `tests/promotion_gate.py`.

Stage 5 (**SPEC-VS-IMPLEMENTATION RE-READ**) added as a formal gate, not a
habit, after the R19 re-read found a missing writer-precedence rule that no
existing test covered:

```text
1 CHARACTERIZE -> 2 IMPLEMENT -> 3 ADVERSARIAL TEETH -> 4 REAL-CORPUS REPLAY
-> 5 SPEC-VS-IMPLEMENTATION RE-READ -> 6 PROMOTE
```

Rationale recorded: FOUR defects in this line all failed in the SAME direction
(over-claiming evidence). Three were caught by stages 3-4; the fourth (R19
writer precedence) was invisible to both -- transport worked, corpus looked
correct, and no test existed because the rule had never been implemented.
**Absence of a test is not evidence of absence of a requirement.** Review effort
should be spent asymmetrically on the over-claiming side.

All frozen invariants collected in one place (ANY-is-not-a-domain; declared
type != runtime proof; AST containment != symbol identity; resolved call edge
only as good as its receiver typing; nested transforms don't donate inputs;
specificity selects the effective writer without erasing broader ones;
state-flow certainty != origin certainty; observed callsite types aren't an
exhaustive runtime model).

`tests/promotion_gate.py` structurally verifies every PROMOTED fact has a
verdict report, a registered gate with runner + checker, and a TRACKS entry.
**It caught a real gap on its first run** -- `ContextStateFlowFact` was promoted
and gated but never named in TRACKS.md. Fixed.

Capability boundary stated precisely (R19):
```text
property-specific overwrite semantics : IMPLEMENTED + TESTED
mixed-origin container on fixture     : DEMONSTRATED
mixed-origin container on Corpus B    : NOT YET OBSERVED END-TO-END
```

## JS-PROV-R20 — NestJS decorator origin characterization (no implementation)
Report: `docs/corpus-scans/js-prov-r20/`. Chosen ahead of validator-semantics
profiling because decorators encode the source family AT the controller
boundary, with no opaque transform in the way.

**Adversarial teeth ALL PASS — origin comes from the ANNOTATION, never the name:**
```text
@Query() body    -> [Query]     (NOT Body)
@Body()  query   -> [Body]      (NOT Query)
@Param('id') headers -> [Param] (NOT Headers)
@Headers('h') param  -> [Headers](NOT Param)
@Body() body, unrelated -> idx1:[Body]  idx2:[NONE]
@Param+@Body+@Query on one method -> three families bound independently
NotAController (same shape, no decorators) -> no annotations at all
undecorated method in decorated class -> correctly excluded
alias + destructuring -> ordinary assignments over a REF-linked parameter
```

**NOT PRESERVED: decorator ARGUMENTS.** `@Param('id')` / `@Headers('h')` expose
`parameterAssign=0` and no AST children; the key exists only inside the
annotation's `code` string. FAMILY is establishable; the SPECIFIC KEY is not,
and must not be recovered by parsing code text (R13: code strings are not
identities). `@Body()`/`@Query()` unaffected.

**REAL CORPUS (truthy @9b9a61be): 39 route methods, BODY 16 / QUERY 6 /
PARAM 12 / HEADERS 0** -- exactly matching R02's independently-measured source
ground truth. 34 parameters with an establishable HTTP origin and NO transform
in between. The 16 other decorators (@Req/@Res/@GetUser/@UploadedFile) are
correctly NOT classified as HTTP families.

Nominated next: **JS-PROV-R21 — ExternalInputOriginFact promotion on the NestJS
decorator path** (`evidence = NESTJS_PARAMETER_DECORATOR`, `established = true`)
-- the first route where `established` is defensible WITHOUT a third-party
semantics profile. Then second-corpus replay, then (last, riskiest) curated
joi/zod/yup semantics.

DISCIPLINE NOTE: every tooth passed first run, which has not happened before in
this line. That is a caution, not a celebration -- the decorator path is easy
precisely because NestJS states the answer declaratively, so it exercises far
LESS of the inference machinery than Koa did. A clean result here is WEAKER
evidence about the engine than a messy one was.

## JS-PROV-R21 — ExternalInputOriginFact promotion, NestJS decorator producer (IMPLEMENTATION)
Report: `docs/corpus-scans/js-prov-r21/`. **JS_PROV_R21=12/12.**
**`ExternalInputOriginFact` is PROMOTED** -- the last conspicuous unpromoted fact.

Frozen family-level mapping (closed set of four): `@Body()`->HTTP_BODY,
`@Query()`->HTTP_QUERY, `@Param(...)`->HTTP_PARAM, `@Headers(...)`->HTTP_HEADERS,
`evidence=NESTJS_PARAMETER_DECORATOR`, `established=true`,
**`origin_key=UNKNOWN` ALWAYS** (explicit, never parsed from annotation code --
R20 measured the key exists only in the code string, and code strings are not
identities per R13).

All four misleading-name controls are permanent gate assertions
(`@Query() body`->QUERY, `@Body() query`->BODY, `@Param() headers`->PARAM,
`@Headers() param`->HEADERS), plus: undecorated sibling gets NOTHING;
undecorated class of identical shape NOTHING; undecorated method in a decorated
class NOTHING. **Boundary/dataflow separated and gate-enforced**: derived locals
consume the boundary fact and NO derived entry may claim decorator evidence.

**REAL CORPUS (truthy): 34 established facts, BODY 16 / QUERY 6 / PARAM 12 /
HEADERS 0 -- EXACT match to R02's independently-measured baseline** (established
before this producer existed, so not self-referential). 16 non-HTTP decorators
(@GetUser x7, @Req x4, @Res x4, @UploadedFile x1) correctly UNKNOWN, NEVER
guessed -- noting `@GetUser` genuinely carries request-derived data, so
abstaining LOSES real information. That is the correct trade: a closed set that
abstains is maintainable; inferring families from decorator names is the lexical
heuristic this whole line exists to avoid.

**Same neutral fact, two unrelated evidence chains:**
```text
Koa:    module->callback->middleware role->state write->transform -> TRANSFORM_INPUT_ONLY
NestJS: decorator->parameter                                      -> ESTABLISHED
```
What a framework DECLARES determines how much a static analyzer must RECONSTRUCT.

Next: second-corpus replay of the WHOLE chain (R02 lesson: one corpus is not
generalization), then last/riskiest curated joi/zod/yup value-preservation.

## JS-PROV-R22 — second-corpus portability replay (NO implementation changes)
Report: `docs/corpus-scans/js-prov-r22/`. Post-promotion EXTERNAL VALIDITY gate.
All six promoted facts run FROZEN (hashes in evidence/FROZEN_HASHES.txt).

CORPUS C: `lujakob/nestjs-realworld-example-app` @ c1c2cc4e (35 TS, 1174 LOC,
5 controllers, 6 services, 6 DTOs, 2 pipes, multi-module). **ESM** (137 import /
41 export / 0 module.exports) vs Corpus B's CommonJS -- deliberately different.

```text
LAYER                          produced established abstained WRONG
1 module/export identity            0        0        174      0
2 returned-function identity        0        0         -       0
  ObservedParameterType            60       25         -       0
3 framework registration            0        0        591      0
4 callback/middleware identity      0        0         -       0
5 context/property state flow       0        0          0      0
6 ExternalInputOriginFact          20       20          9      0
7 TransformInputOriginFact          0        0         -       0
```
**demonstrably wrong = 0 at EVERY layer.**

Layer 6 validated against INDEPENDENT source ground truth (grep, not the
producer): BODY 6 / QUERY 2 / PARAM 12 / HEADERS 0 = **exact match** on a corpus
never seen during R21 promotion. All 9 `@User(...)` abstained as
DECORATOR_NOT_IN_CLOSED_SET -- a SECOND differently-named custom decorator that
plainly carries request data, and no special case was added for it.
`derived=1`: the dataflow consumer fired on REAL code (fixture-only in R21).

Pre-registered categories assigned: layers 1-2 EXPECTED_UNSUPPORTED (ESM vs
R14's CommonJS-only producer); layers 3,4,5,7 EXPECTED_UNSUPPORTED (NestJS
establishes origin at the decorator boundary -- no router registration, no
middleware context, no opaque transform); 1 FRONTEND_GAP (`.spec.ts`, known
ignore since JS-REAL-R01). **Every zero is a clean abstention with a named
cause.**

```text
PORTABILITY: PASS -- no corpus-specific changes, zero false evidence,
meaningful facts on independent real code.
```

**HONEST LIMIT:** Corpus C validated ONE of seven layers on a second corpus.
The other six abstained cleanly, which is correct behaviour but is NOT evidence
they would work if exercised. NestJS boundary producer is now TWO-corpus; the
Koa chain remains ONE-corpus.

DOMINANT GAP: **ESM module identity** -- R14 resolves CommonJS only, and ESM is
the dominant modern style (137 imports vs 2 requires here). Invisible on Corpus
B, which happened to be CommonJS throughout. Nominated next:
**JS-PROV-R23 — ESM Export Identity** (acceptance: Corpus C module identity > 0
with zero wrong resolutions; Corpus B CommonJS unchanged; all gates unchanged),
THEN a third corpus exercising the Koa chain, and only LAST the curated
joi/zod/yup profile.

## JS-PROV-R23a — ESM export identity: fixture & control suite (characterization)
Report: `docs/corpus-scans/js-prov-r23a/`. No implementation, no downstream replay.

**CORRECTS R22's DIAGNOSIS.** R22 said layer 1 produced 0 because "Corpus C is
ESM; R14 is CommonJS-specific." Measured directly, that is NOT the mechanism:
**jssrc2cpg LOWERS ESM to CommonJS-shaped nodes**, so all six export shapes
already produce exactly the `exports.X = Y` assignments R14 reads, WITH
module-qualified declaration identity on the RHS -- including
`export { fOrig as fRenamed }` correctly resolving to fOrig's declaration.

**The ACTUAL gap is IMPORT BINDING.** ESM named imports lower to
`local = require(spec).member`, so R14 binds the local to the module OBJECT,
not the member. Default and namespace imports lower IDENTICALLY
(`var x = require("./lib")`) and cannot be told apart in the lowered form.

**Better input exists:** `cpg.imports` exposes `entity=<spec>:<member>` and
`as=<local>` directly -- no lowering, no code-string parsing. Correct input for R23b.

MUST-ABSTAIN (measured): `export *` (binds an ANY-typed namespace local, no
member identity); **namespace import** (`entity=./lib:ns` where `ns` is a
SYNTHETIC, not a real export -- sharpest fabrication risk, a resolver must
reject entities not matching an actual export assignment); dynamic `import()`
(not an IMPORT node at all); unresolved modules.
SURPRISE: `export default <expression>` DOES carry identity
(`danger.ts::program:<lambda>1`) and need not abstain.
NOT CLOSED: re-export RHS is a field access on the module object (one more hop).

Nominated next: **JS-PROV-R23b** — build the import-binding producer on
`cpg.imports`, validated against INDEPENDENTLY ENUMERATED Corpus-C ground truth
(grep-derived, as Layer 6 was). Acceptance: every established binding matches
source; export*/namespace/dynamic/unresolved all abstain; ZERO fabricated
members. ONLY THEN freeze and replay downstream.

DISCIPLINE: this corrects my own R22 verdict. "ESM, therefore unsupported" was
plausible, fit the zero, and was wrong -- scoping R23 as "add ESM export
support" would have reimplemented working machinery and left the real gap
untouched. Second instance (after R12's module-level coincidence) of a
diagnosis accepted because it explained the symptom without being separately
verified. **Measure the cause; don't infer it from the symptom.**

## JS-PROV-R23b — import-binding identity (IMPLEMENTATION)
Report: `docs/corpus-scans/js-prov-r23b/`. **JS_PROV_R23B=9/9.**
`import_bindings.sc` + `import_binding_identity.py` -> **ImportBindingIdentityFact**.
**Downstream layers remain FROZEN and were NOT replayed** -- by design, so
downstream improvement cannot serve as the promotion criterion for the fact.

FROZEN CONTRACT (one rule, no per-shape special cases): *an import establishes
member identity ONLY when its imported entity matches an independently
established export identity in the resolved target module.*

**MEASURED, NOT ASSUMED:** `cpg.imports` does NOT distinguish default from
namespace imports -- `isWildcard` is **false for BOTH**, and both report the
LOCAL ALIAS as the member (`fDefault`/`ns`). A producer written from the API
surface would have branched on `isWildcard` and fabricated a member named `ns`.
Both abstain by the single rule instead. **Default imports are NOT establishable
by this route** -- measured limitation, recorded not designed around.

Preregistered table met exactly: `{f}` establishes; `{f as g}` establishes
g->SOURCE member f (not the alias); default/namespace/missing-export/unresolved/
`export *`/dynamic all abstain.

```text
CORPUS C: observed 220 | established 63 | abstained 157
  independent source ground truth: 206 named-member bindings
    79 RELATIVE (the only establishable class) | 127 BARE (must abstain)
  => 63 of 79 establishable (80%); 144 correct external abstentions
  ZERO fabricated members
```
Keeping observed vs established SEPARATE matters here: raw 63/220 reads as 29%
and badly understates the producer, when 127 misses are external packages.

DOMINANT GAP: **re-export chains** (`export {x} from './y'`) -- 9 of 13 relative
abstentions, the gap R23a already identified, needing one more hop. Still open.

Next: freeze R23b and replay downstream on Corpus C to see whether layers 1-2
begin firing (the ordering the design requires), then **JS-PROV-R24** — an
independent Koa corpus, to convert the Koa chain's "safe abstention" evidence
into genuine multi-corpus evidence.

## JS-PROV-R23c — frozen downstream replay + accounting reconciliation (observational)
Report: `docs/corpus-scans/js-prov-r23c/`. NO fixes, NO wiring, NO re-export work.

**Downstream production change: NONE.** L1/L2/L3/L5 unchanged at 0; L6 unchanged
at 20 (BODY 6/QUERY 2/PARAM 12). Nothing previously established changed; ZERO
newly-wrong identities.

**Cause is INTEGRATION, not semantics:** consumer-wiring check shows
`import_bindings.tsv` is read by `import_binding_identity.py` ONLY --
`module_specifier_resolution.py` still reads `require_bindings.tsv`.
**ImportBindingIdentityFact is a standalone fact with no consumer.** R23b
validated the fact; it did not integrate it. The replay's value is making that
distinction visible instead of letting "9/9" imply the chain had moved.

**ACCOUNTING DELTA CLOSED -- and my R23b hypothesis was WRONG.** R23b speculated
the 3-binding remainder was "barrel index.ts counting". Measured triple-by-triple:
```text
IN SOURCE BUT NOT OBSERVED (exactly 3, all one file):
  tag/tag.controller.spec.ts  ./tag.controller  TagController
  tag/tag.controller.spec.ts  ./tag.service     TagService
  tag/tag.controller.spec.ts  ./tag.entity      TagEntity
79 source = 76 observed + 3 in the omitted .spec.ts (known jssrc2cpg ignore)
76 observed = 63 established + 13 abstained   (verified identity, True)
13 = 9 re-export + 4 unresolved
```
**CORRECTED RECALL: 63/76 observable relative bindings (83%)** -- the 3 are a
frontend omission, not a producer miss. Three denominators retained as DIFFERENT
measurements: 63/220 (29%, not a producer metric), 63/79 (80%), 63/76 (83%, actual recall).

Re-export gap (9 of 13) PARKED -- it blocks nothing, since downstream has no consumer.

DISCIPLINE: **third instance** of a plausible explanation failing on measurement
(R12 module-level coincidence; R22 "ESM therefore unsupported"; R23b "barrel
counting"). Pattern named: *the failures cluster on explanations offered for
numbers that were otherwise satisfying.* Requiring deltas to close ARITHMETICALLY
(79=76+3, 76=63+13) is cheap and should be routine.

Next: **JS-PROV-R24 — independent Koa corpus** (converts the Koa chain's
abstention-safety evidence into multi-corpus portability evidence). Wiring
ImportBindingIdentityFact into a consumer is a separate, later, isolated revision.

## JS-PROV-R24 — independent Koa corpus: BLOCKED (experiment did not run)
Report: `docs/corpus-scans/js-prov-r24/`. Criteria PREREGISTERED before any
candidate was inspected (`PREREGISTERED_CRITERIA.md`: E1 Koa APPLICATION,
E2 router registrations, E3 >=8 routes, E4 middleware chain, E5 cross-middleware
ctx write/read, E6 CommonJS, E7 independently authored).

**No candidate satisfied them. Criteria were NOT relaxed.** Screened:
`koajs/examples` (2 routes, FAIL E1/E3), `chenshenhai/koa2-note` (5 routes,
FAIL E1/E3), plus 5 unretrievable candidates.

**The declined relaxation:** dropping E3 from 8 to 5 would have let R24 "run"
on koa2-note and produce numbers. A threshold moved AFTER seeing which candidate
is available is not a threshold -- and it is the same error class R23c named.

Non-qualifying smoke observation (koa2-note, frozen, **NOT portability
evidence, must not be cited as R24 results**): L1 0 / L2 0 / L3 0 / L5 0 /
L6 0, with 0 wrong evidence -- consistent with a tutorial repo whose 5 routes
use inline handlers rather than module-crossing middleware chains. It measures
ABSENCE OF OPPORTUNITY, exactly the Corpus-C situation preregistration exists
to avoid.

```text
KOA CHAIN EVIDENCE STATUS (unchanged, precisely stated):
  NestJS boundary producer portability : TWO corpora
  Koa chain portability                : ONE corpus (Corpus B)
  Koa chain abstention-safety          : TWO corpora
```

WHAT WOULD UNBLOCK: GitHub CODE search on `router.post(` co-occurring with
`module.exports` and middleware arity >=3 (repository-NAME search is what failed
here); or a private/industrial Koa service; or accepting a same-family corpus
with the weaker claim stated.

Next: either retry selection with the code-search strategy, or proceed to
**R25 — ImportBindingIdentityFact WIRING**, which is independent of corpus
availability and has a concrete R23c acceptance target (L1/L2 production on
Corpus C becomes non-zero; Corpus B CommonJS and all gates unchanged).

DISCIPLINE: a blocked experiment is worse than a passing one and BETTER than a
fitted one. Reporting five layers at zero as "portability confirmed, clean
abstention" would have been true sentence-by-sentence and misleading as a whole.
Preregistration cost one command and prevented it. Keep it as a standing
requirement for corpus-based milestones, as the spec-vs-implementation re-read
became stage 5 of the promotion gate.

## JS-PROV-R25 — ImportBindingIdentityFact consumer integration (INTEGRATION ONLY)
Report: `docs/corpus-scans/js-prov-r25/`. Expectations PREREGISTERED before
implementation. R23b producer FROZEN and hash-verified. **JS_PROV_R23B=17/17**
(R23b's 9 producer teeth + R25's 8 consumer teeth); R14 9/9, R12 28/28 unchanged.

Fixes the dead-end R23c exposed: correct producer, no consumer.

**All preregistered invariants held:** I1 hash-identical producer; I2 Corpus B
CommonJS unchanged (45 facts / 9 validate() resolutions); I3 no default/namespace
established via wiring; I4 the 13 abstentions remain abstentions; I5 moved ⊆
established; I6 L6 still 20; I7 WRONG=0; I8 movement traced per layer.

**DECISIVE NEGATIVE CONTROL (the gate's load-bearing tooth):**
```text
R23b established : fDecl, fAliased      R23b abstained : fDefault, ns, viaReexport
downstream moved : fDecl, fAliased      abstained that moved : NONE
```
`ns` is present in `cpg.imports` with a plausible entity `./lib:ns`; a consumer
keyed on import PRESENCE would have carried it downstream and fabricated a
member. Keying on the ESTABLISHED SET stops it. That distinction is invisible
when everything passes -- hence the negative control, not the positive one, is
load-bearing.

```text
CORPUS C by layer:      R23c  R25   predicted
  L1 module/export         0    9   RISE
  L2 returned-function     0    0   0
  L3 framework reg         0    0   0
  L5 context state flow    0    0   0
  L6 external input       20   20   20 (must not shrink)
```
All 9 L1 facts carry `ESM_IMPORT_BINDING_IDENTITY` + `enabled_by_import_binding`
(e.g. `User('id')` <- user/user.decorator.ts:User). **9 of 63 established
bindings produced downstream facts** -- preregistered as the expected shape; the
63 are AVAILABLE identities, not pending obligations, so neither 63 nor 9/63 is
a success rate.

R23b and R25 stay SEPARATE milestones: R23b = *can ESM import identity be
established correctly?* (yes); R25 = *does the architecture actually USE it?*
(yes, 0->9).

**R24 remains BLOCKED and is NOT renumbered around.** Resume under the ORIGINAL
E1-E7 criteria if an eligible Koa corpus is obtained. Otherwise the re-export
hop (still 9 of 13 relative abstentions, now the binding constraint on further
L1 growth) is the next isolated revision.

### JS-PROV-R25 CLOSEOUT — PROMOTED and FROZEN
All nine closeout criteria RE-VERIFIED at closeout (not carried forward):
producer hashes diff-clean; L1 0->9; 9/9 traceable; negative control holds
(fDefault/ns/viaReexport still downstream-abstained); R14 9/9 + R12 28/28;
L2/L3/L5=0 and L6=20; WRONG=0; CommonJS Corpus B 45 facts all
REQUIRE_BINDING+EXPORT_ASSIGNMENT; measured limit recorded (9 of 63 consumed --
63 is NOT a target or success-rate denominator).

> **JS-PROV-R25: PROMOTED.** ImportBindingIdentityFact is now consumed by
> module/export identity resolution. Corpus C L1 production increased 0->9
> exactly as preregistered, every new fact traceable to an established R23b
> import identity. No R23b-abstained import produced downstream identity,
> including the namespace-import fabrication control. Existing CommonJS
> behaviour and all previously established facts unchanged; demonstrably
> wrong = 0. No further semantic changes are included in R25.

Frozen state tagged: `docs/corpus-scans/js-prov-r25/R25_FROZEN_STATE.txt`
(component hashes + gate results). `ImportBindingIdentityFact` added to
`docs/PROMOTION_GATE.md` and `tests/promotion_gate.py` (now 7 promoted facts).

**Re-export handling is explicitly NOT in R25** -- still 9 of 13 relative
abstentions and now the visible constraint on further Corpus-C L1 growth, but
folding it in would have made R25 a semantics change wearing an integration
label. If pursued: new isolated revision, own freeze, own preregistration, own
negative controls.

Also added to `docs/PROMOTION_GATE.md`: **standing requirement that corpus
eligibility be preregistered before candidate inspection** (from R24), and the
**close-residuals-by-identity-not-narrative** corollary (from R23c).

## JS-PROV-R26 — bounded re-export hop (isolated revision)
Report: `docs/corpus-scans/js-prov-r26/`. Own preregistration + freeze + negative
controls, per R25 closeout. **JS_PROV_R23B=25/25**; R14 9/9, R12 28/28, R21 12/12.

Closes the R23a gap: `export {f} from './x'` -> `exports.f = _x.f` (field access
on a module object, no declaration identity). One hop, transitive, BOUNDED
(depth 8, recorded on the fact); base+member exported STRUCTURALLY, not parsed
from code strings (R13).

```text
FIXTURE: viaReexport ESTABLISHED -> lib.ts::program:fDecl
         chain [reexport.ts:fDecl, lib.ts:fDecl], evidence ...+REEXPORT_CHAIN
         notThere ABSTAIN (member not exported) | spin ABSTAIN (TRUE cycle)
         fromCyc2 ESTABLISHED (terminating mutual re-export, not over-blocked)
CORPUS C: import identities 63 -> 72 (+9, all via chain);
          EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION 9 -> 0;
          L1=9 L2/L3/L5=0 L6=20 unchanged
CORPUS B: 45 facts / 9 validate(), unchanged
```

**J2 CAUGHT A REGRESSION I INTRODUCED.** Widening `module_exports.tsv` 5->7
columns silently zeroed the CommonJS path (`module_specifier_resolution.py`
reads fixed width): **Corpus B fell 45 -> 0 while every gate still passed**,
because no gate exercises Corpus B directly. Fixed with a width-agnostic reader.
A schema widening is not a semantic change -- which is exactly why gates missed it.

**My first cycle control did not test what it claimed.** `cyc1->cyc2->cyc1.realInCyc1`
TERMINATES legitimately (mutual re-export, not a cycle), so the guard was
untested. Added a TRUE non-terminating cycle (`loopa<->loopb`) which abstains
via `REEXPORT_CYCLE`. Both retained: one proves the guard fires, the other that
it does not over-block.

**Three superseded assertions INVERTED IN PLACE, not deleted**, so the behaviour
change stays visible in gate history: "re-export ABSTAINS" -> "RESOLVES via R26";
evidence `==` -> `startswith` (chain suffix); "never reaches the consumer" ->
"reaches it ONLY because R26 established it". The decisive R25 negative control
(only ESTABLISHED bindings move) is untouched and still passes.

DISCIPLINE: two self-inflicted defects in one milestone, both caught by
PREREGISTERED CHECKS rather than gates, with the suite green throughout. Third
such instance in this line. **Gates verify what they were written to verify; a
milestone's preregistered invariants catch what nobody thought to gate.**

## JS-PROV-R26 — re-export chain resolution: IMPLEMENTED, **NOT CLOSED**
Report: `docs/corpus-scans/js-prov-r26/`. Preregistered before implementation.
**NOT PROMOTED. `JS_PROV_R23B=30/31`.**

WORKS (measured): chains resolve transitively to a terminal declaration with the
chain recorded; `missing` member abstains; TRUE cycle (`spin`) abstains and
terminates; `export *` abstains.
```text
realFn -> base.ts::program:realFn  chain=[mid.ts:realFn, base.ts:realFn]
viaTop -> base.ts::program:realFn  chain=[top.ts:realFn, mid.ts:realFn, base.ts:realFn]
CORPUS C established 63 -> 72 (+9, all via re-export chain), exactly the
preregistered upper bound; EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION now 0
CORPUS B CommonJS unchanged (45 facts / 9 validate()); R14 9/9, R12 28/28
```

**WHY NOT CLOSED:** the gate fixture dir already held a differently-designed R26
fixture set (`loopa/loopb` = true cycle, `cyc1/cyc2` = TERMINATING MUTUAL
re-export). I copied my own cyc1/cyc2 in, **overwriting the terminating-mutual
case**, and edited use.ts to match. Reconstructing fixed two teeth; one remains:
```text
FAIL R25 DECISIVE NEGATIVE: no ABSTAINED binding moves downstream :: ['fromCyc2']
```
`fromCyc2` appears in BOTH established and abstained sets -- consistent with a
local-name collision across the merged fixture set, but **NOT DIAGNOSED**. Per
R23c's standing rule, a plausible explanation is not a finding and none is
recorded.

**The red tooth is the fabrication control** -- the one designed to catch an
abstained binding leaking downstream. Worst possible tooth to leave red, and
exactly why R26 is not promoted on "the numbers look right".

NEXT (before further R26 work): rebuild the fixture set cleanly instead of
patching -- per-revision file namespaces (`r26_chain_*`, `r26_cycle_*`,
`r26_mutual_*`), assert local-binding names unique across the set, then re-run;
if `fromCyc2` still appears in both sets, DIAGNOSE it rather than renaming around it.

DISCIPLINE: two failures, both mine. (1) Copied files into a shared gate fixture
directory without checking its existing design -- a test artifact treated as
scratch space. (2) Corpus C hit its preregistered target and Corpus B was
unchanged, creating real pressure to call the red tooth a fixture artifact and
promote. **A revision whose measured behaviour is good and whose fabrication
control is red is not nearly done -- its most important claim is unverified.**

### JS-PROV-R26 RECOVERY — CLOSED
**JS_PROV_R23B=33/33** (was 30/31); R14 9/9, R12 28/28.

**Open question answered WITH EVIDENCE: the defect was the GATE'S IDENTITY KEY,
not the resolver.** `app.ts:17 import { fromCyc2 } from './cyc1'` -- the R23a-era
file ALSO imported a binding named `fromCyc2`. Two legitimately distinct import
records in different modules shared one human-readable local name; the gate keyed
`est`/`abst` on local name alone, collapsing one established + one abstained
record into an apparent contradiction. The resolver was correct throughout.
This is exactly why the recovery FORBADE renaming before diagnosis -- renaming
would have gone green while leaving the coarse key, and the next collision, in place.

Recovery in preregistered order: fixtures REBUILT under `r26_chain_*/r26_cycle_*/
r26_mutual_*/r26_missing_*/r26_star_*` (contaminated set preserved at
`evidence/contaminated_snapshot/`); R23a originals untouched; both invariants
added as PERMANENT teeth; `ESTABLISHED n ABSTAINED` computed explicitly = {};
origin traced before any rename.

```text
CORPUS C  63 -> 72 (exactly the preregistered bound), disjointness {}, L1 = 9
CORPUS B  CommonJS unchanged (45 facts / 9 validate())
```

**R26 CLOSED.** Re-export chain resolution folded into ImportBindingIdentityFact.

Standing rules added to `docs/PROMOTION_GATE.md`: **FIXTURE-DIRECTORY RULE**
(promotion fixtures are versioned experimental inputs, never overwritten; new
revisions get their own namespace), **R26-FIXTURE-INTEGRITY**, **R26-SET-DISJOINTNESS**.

DISCIPLINE: the instinct on seeing the overlap was that the resolver had a
contradiction. It did not. **A coarse gate key can manufacture the appearance of
an analyzer defect -- a red tooth is evidence that SOMETHING is wrong, not
evidence about WHAT.** That cuts both ways: 30/31 was not "basically passing",
and it was also not proof the resolver was broken. Both readings were
unjustified until the two records were traced to their modules.

## JS-PROV-R27 — gate assertion-key audit (follow-up to R26)
Report: `docs/corpus-scans/js-prov-r27/`. R26's defect -- *gate assertions keyed
on a non-unique attribute* -- treated as a CLASS and audited across all gates.

```text
GATE          KEY                          unique on fixture   collides on real corpora
js-prov-r08   callee short name            YES (5/5)           --
js-prov-r09   declaring-method short name  YES (1/1)           --
js-prov-r14   CALL CODE STRING             YES (3/3)           YES: validate(schema) x9 (45->32)
js-prov-r21   (method short name, param)   YES (11/11)         YES: ('delete','params') (20->19)
js-prov-r23b  local binding name           YES (fixed in R26)  --
gate24-ts2/source-r02/poly-r01  node/record ID -- structurally safe
```

**No gate is currently wrong** -- all key uniquely on their own fixtures. But
four are correct *by luck of fixture content, not by construction*, and
demonstrably collide on production code. `js-prov-r14` is sharpest: it keys on
CALL CODE STRINGS, which R13 established are not identities -- the gate was
doing what the engine is forbidden to do.

**NEAR-MISS worth recording:** the first audit reported r08 colliding
(`installReal`/`installBoth`, 10->8). That was MY AUDIT HARNESS copying
`fixture/*.ts` AND `*.js` while `run.sh` copies only `t.ts`; re-run correctly =
5/5 unique. Same error class INVERTED -- R26 was a coarse key manufacturing an
apparent RESOLVER defect, this was a coarse harness manufacturing an apparent
GATE defect. Both times the measurement apparatus, not the subject, was at
fault. It did surface a real minor issue: stray dead fixture
`js-prov-r08/fixture/gate.js` (never copied by run.sh), now removed.

REMEDIATION: `R26-FIXTURE-INTEGRITY` added as a permanent tooth to all four
coarse-keyed gates -- each asserts its own keys are distinct, converting a
SILENT failure mode into a LOUD one. Keys deliberately NOT rekeyed to ids:
larger change, own regression risk, and the audit shows it is not currently
needed.

```text
JS_PROV_R08=13/13  R09=12/12  R14=10/10  R21=13/13
JS_PROV_R12=28/28  R17=18/18  R23B=33/33  JS_STATE_R07=31/31
PROMOTION_GATE=PASS (7 promoted facts)
```
RESIDUAL: rekeying r14 off code strings remains open.

DISCIPLINE: **"passing" and "correct by construction" are different properties,
and a green suite cannot distinguish them.** Four gates were both.

## JS-PROV-R24 — RESUMED AND COMPLETED (negative result)
Report: `docs/corpus-scans/js-prov-r24/JS_PROV_R24_RESUMED.md`. Eligible corpus
found under the ORIGINAL unmodified E1-E7 criteria; experiment ran; **the Koa
chain did NOT reproduce.**

CORPUS D: `gothinkster/koa-knex-realworld-example` @ 602e2341 (36 JS, 1795 LOC).
E1-E7 all verified -- notably E5 required `ctx.state.user` written in
`middleware/user-middleware.js` and read in 4 other files (`ctx.body`/`ctx.status`
were REJECTED as response writes, not cross-middleware state).

```text
LAYER                        Corpus D   Corpus B
1 module/export identity         49        45     <- REPRODUCED
2 returned-function               0         2
  ObservedParameterType          52 (30 est)
3 framework registration          0        14     <- DID NOT REPRODUCE
4 callback identity               0        33
5 context state flow              0        23
demonstrably wrong                0         0
```

**CAUSE — a previously recorded, never exercised scope boundary.** Corpus D uses
`const router = new Router()`; its 15 registration receivers resolve with
`type = koa-router` (framework identity CORRECT) but `isParam = NO`, and
`framework_registration.py:78` does `if not param_method: continue`. R09
consumes receiver-domain evidence for PARAMETER receivers -- the mechanism built
for Corpus B, where routers cross module boundaries as arguments.
**JS-PROV-R10 recorded exactly this limitation and it was never exercised until
now.**

Clean abstention, not a wrong answer -- but the preregistered criterion was
*same semantic conditions -> same facts*, and Corpus D presents the same
condition in a different syntactic shape.

```text
Koa chain portability : FAILS on a second corpus, for a NAMED reason
Layer 1 portability   : ESTABLISHED on two corpora
Abstention safety     : holds (3 corpora)
```

Nominated next: **JS-PROV-R29 — direct-receiver framework registration** (accept
a receiver whose OWN resolved type is in the framework profile, not only one
typed via ObservedParameterTypeFact; the evidence is already present and
correct). Acceptance: Corpus D L3 15/15 with 0 wrong; Corpus B unchanged at 14;
a non-profiled directly-typed receiver still yields 0; all gates green.

DISCIPLINE: resuming the blocked experiment was worth it precisely BECAUSE it
produced a negative. Dropping it would have left the Koa chain carrying an
implicit generality claim that one differently-shaped corpus disproves. It also
vindicates keeping R10's recorded-but-unexercised limitation in the ledger --
hypothetical for four milestones, now the reason a whole chain produced nothing.

## JS-PROV-R29 — direct-receiver framework registration (IMPLEMENTATION)
Report: `docs/corpus-scans/js-prov-r29/`. **JS_PROV_R29=9/9** (own isolated
gate); all gates green, PROMOTION_GATE=PASS. Fixes the limitation R24 exposed.

`framework_registration.py` now also accepts a receiver whose OWN resolved type
is in the framework profile, not only parameter receivers. Profile unchanged as
a concept; `koa-router` added as an EXPLICIT second entry beside `@koa/router`
(never by normalising specifier strings).

**Does NOT reintroduce the R09 hazard:** R09 distrusted `recv_type` because
jssrc2cpg mis-propagates types onto PARAMETERS (interprocedural). A DIRECT LOCAL
takes its type from its own initializer. Measured: R07 `direct`->@koa/router,
`fr`->FakeRouter (both correct); Corpus D `router`->koa-router 15/15.
Parameter path untouched; `identity_evidence` distinguishes
RECEIVER_DOMAIN_EVIDENCE vs DIRECT_RECEIVER_TYPE.

DECISIVE NEGATIVE: `fr.get("/no",h)` is syntactically identical to
`real.get("/ok",h)`; only profile membership of the receiver TYPE separates them.
FakeRouter / object-literal / globalThis receivers all yield nothing.

**K1 DEVIATION, recorded not waived:** Corpus B went 14 -> 18. Parameter path
genuinely unchanged (14 identical); the 4 additions are `app.use` on a
`koa`-typed local, verified against source (12 `app.use(` exist, 4 resolve).
Correct new facts, L5 unchanged at 23. But K1 should have said *"the
parameter-receiver path is unchanged"*, not *"Corpus B unchanged at 14"* --
**a preregistered invariant that conflates a mechanism with a count will
eventually be violated by a correct change.**

```text
R24 RE-RUN, Corpus D:   before R29   after R29
  L3 framework registration    0         28      <- Layer 3 now TWO-CORPUS
  L4 callback identity         0          0
  L5 context state flow        0          0
  demonstrably wrong           0          0
```
L5 blocked by ONE new cause: 23 abstentions, all WRITER_IDENTITY_UNKNOWN_OR_STUB.
Corpus D's callbacks are IMPORTED controller functions, so callback identity
needs the module-export path R14/R25 built -- **not currently consulted by
`context_state_flow`**. Same shape as R23c: a correct producer a consumer does
not read. Corpus D has genuine `ctx.state.user` cross-middleware state, so the
opportunity is real and unexercised.

Nominated next: **JS-PROV-R30 — wire ModuleExportIdentityFact into
context_state_flow callback resolution.** Acceptance: Corpus D L4/L5 > 0 with
0 wrong; Corpus B unchanged at 33 callbacks / 23 flows; all gates green.

DISCIPLINE: the R29 fixture initially went into the js-prov-r09 gate dir and
broke FOUR unrelated assertions (two files each declaring `FakeRouter` -- a
short-name collision perturbing type recovery). **Third independent confirmation
that fixture merging produces misleading gate states (R26, R27, here). One
fixture set per revision, never merged.**

## JS-PROV-R30 — module-export identity in callback resolution (INTEGRATION ONLY)
Report: `docs/corpus-scans/js-prov-r30/`. R14/R25 producers FROZEN and
hash-verified. Gates: R12 28/28, R29 9/9.

Implemented: callback arguments that are FIELD ACCESSES on imported module
objects (`router.get('/x', ctrl.get)` with `ctrl = require('../controllers')`)
resolve through the same export facts R14/R25 produce, keyed on
`(file, base local, member)` -- on the ESTABLISHED export record, never on the
presence of an import.

**CORPUS D still 0 -- and the abstention is CORRECT.** Traced concretely, not
assumed:
```text
routes/articles-router.js   router.get("/articles", ctrl.get)
                            const ctrl = require("../controllers")
controllers/index.js        module.exports = { users, tags, profiles, articles }
exported fact               controllers/index.js  member=<none>  kind=BLOCK
```
Corpus D routes through a BARREL (directory import -> `controllers/index.js`)
exporting an OBJECT LITERAL, whose members carry no individual identity at BLOCK
level. **Pre-existing object-literal-export gap (known since R13, re-measured in
R23a as PARTIAL), not an R30 defect** -- but Corpus D is the first corpus where
it blocks an entire chain.

```text
PREREGISTERED     Corpus B: 23 flows IDENTICAL, all MUST, all
                  MODULE_EXPORT_IDENTITY; no fact lost; none added   MET
                  Corpus D: L4>0, L5>0                               NOT MET
                  no export-abstained callback moves downstream      MET
                  demonstrably wrong = 0                             MET
```
The MECHANISM-based wording (your K1 correction) is what makes this clean:
consumer correct, producer correct, blocker is a third thing neither claims.

DECISIVE NEGATIVE holds, and Corpus D is its strongest instance: `ctrl` is
unambiguously imported and observed, its export record ABSTAINS, and nothing
downstream moved.

Nominated next: **JS-PROV-R31 — object-literal export member identity**
(`module.exports = {a,b}` lowers to a BLOCK whose member assignments ARE
individually present -- same shape as R26's re-export hop and R23a's
destructuring finding). Acceptance: Corpus D L4>0 and L5>0; Corpus B 23 flows
identical; a member the literal does NOT contain still abstains; gates green.

DISCIPLINE: R30 produced NO movement and that is the CORRECT outcome. The
temptation was to keep patching until Corpus D moved -- the barrel is one more
hop and R26 showed such hops are usually recoverable -- but that would have made
R30 a semantics change wearing an integration label, exactly the error R25
avoided. Also: the cause was TRACED (`ctrl.get` -> `controllers/index.js` ->
inspect its exported fact), not inferred as "probably a barrel". Three earlier
diagnoses in this line were plausible and wrong (R12, R22, R23b).

## JS-PROV-R31 — object-literal export member identity
Report: `docs/corpus-scans/js-prov-r31/`. **Succeeds as a MEMBER-IDENTITY result;
the Corpus-D chain remains blocked for a NEW named reason** -- the split the
preregistration explicitly anticipated and required be stated.

`module.exports = {a,b}` lowers to a BLOCK whose member assignments are
individually present (`_tmp_0.a = a`). Statically named members now emit as
their own export rows:
```text
named: localFn          static key + resolvable RHS  -> ESTABLISH
fromDep: realDep.thing  static key, RHS module member -> kind=CALL -> R26 hop
[dynKey]: localFn       COMPUTED key (indexAccess)    -> NOT emitted (abstain)
...realDep              spread                        -> NOT emitted (abstain)
```
**M1 holds -- a static key ALONE is not sufficient**: member rows carry the same
rhs/kind columns as every other export row, so a member whose RHS lacks
declaration identity still abstains. Nothing special-cased to make members count.

CORPUS B: 23 flows IDENTICAL, all MUST, all MODULE_EXPORT_IDENTITY, none
lost/added. CORPUS D: L3 28, **L5 still 0**.

**NEW BLOCKER, traced not inferred:**
`const ctrl = require("../controllers").articles` -- import-time member
selection -- then `ctrl.get`. The barrel members NOW RESOLVE (R31 working:
`articles -> { bySlug(...); get(ctx); ... }`) but `articles`'s RHS is a
STRUCTURAL OBJECT TYPE, not a module file, so the second member lookup has no
export table. Distinct from the object-literal gap R31 just closed.

```text
CAUSAL CHAIN (3 of 6 steps produced NO movement, each null CORRECT):
R24 second corpus fails at L3 -> R29 direct-local identity closes L3 (0->28)
 -> L4/L5 still fail -> R30 consumer wiring correct (still 0, CORRECT)
 -> upstream export member absent -> R31 member identity (still 0, CORRECT)
 -> import-time member selection remains
```
Materially stronger than "missed Corpus D, added support until it passed."

**R30 PRESERVED as a successful NULL INTEGRATION EXPERIMENT** -- R31 does not
retroactively make it unsuccessful; R30's consumer did exactly what was asked
and its zero was correct for the facts then available.

DISCIPLINE: the preregistration's most useful clause allowed R31 to SUCCEED
while the chain stayed blocked. Without it the honest outcome would have read as
failure and the pressure would have been to keep hopping until Corpus D moved.
That pressure was real -- the next hop is visible and probably small -- but it
is a DIFFERENT mechanism, and taking it inside R31 would have made the milestone
unfalsifiable: any amount of work could be justified as "finishing" it.

## JS-PROV-R32 — import-time member selection: characterization (no implementation)
Report: `docs/corpus-scans/js-prov-r32/`. Investigating R31's named blocker.

**It is TWO defects, and one is a LATENT FABRICATION, not a miss.**

**DEFECT A (SOUNDNESS).** `const ctrl = require("../controllers").articles`
-> `require_bindings.tsv` records `spec=../controllers local=ctrl`, **dropping
`.articles`**. `ctrl` is bound to the WRONG MODULE. `local_defs.tsv` holds the
truth (`kind=<operator>.fieldAccess`, code=`require("../controllers").articles`).
Measured on Corpus D:
```text
ctrl.* used:            bySlug comments del favorite feed get getOne post put
WRONG module exports:   users tags profiles articles
RIGHT module exports:   bySlug get getOne post put del feed favorite comments
overlap:                NONE -> nothing wrong produced, BY LUCK not soundness
```
A router written `ctrl.users` would resolve against `controllers/index.js`, find
a REAL member, and establish a FABRICATED identity. **R31's zero on Corpus D was
a clean abstention by coincidence of naming, not by construction.**

**DEFECT B (coverage).** `controllers/index.js` member `articles` has an RHS
that is itself a require-bound local (`articles -> ./articles-controller`), so
it denotes a MODULE, but is recorded as an anonymous structural object type
(`kind=IDENTIFIER`, reBase/reMember empty). `articles-controller.js` DOES export
`get` as METHOD_REF (R31 already emits it) -- the terminal fact exists, only the
link is missing.

Both are joins over ALREADY-EXPORTED facts; no new frontend extraction implied.

Nominated next: **JS-PROV-R33 — fix DEFECT A alone**, preregistered as a
SOUNDNESS fix independent of any coverage goal. Acceptance: `require(x).member`
binds to the member's module or ABSTAINS, never to the outer module; a fixture
where outer and inner modules SHARE a member name must not resolve against the
outer; Corpus B unchanged; gates green. Defect B follows separately.

DISCIPLINE: this began as a COVERAGE question ("why is Corpus D still blocked").
The coverage answer is the less important half. The soundness defect was visible
only because the consumer-side binding was CHECKED AGAINST SOURCE rather than
taken at face value -- `ctrl -> ../controllers` is a well-formed, plausible,
confidently wrong record. **Same shape as R09's receiver type, R13's fabricated
callee, R23a's `isWildcard`: four separate layers, and every time the record
looked exactly like a correct one.**

## JS-PROV-R33 — attempted and REVERTED (nothing in the engine)
Report: `docs/corpus-scans/js-prov-r33/`. Gates at reverted state ALL GREEN:
R14 11/11, R23B 33/33, R12 28/28, R29 9/9.

**The shared-name fixture UNMASKED Defect A exactly as intended** (preserved at
`js-prov-r33/fixture/`):
```text
outer.js  module.exports = { shared: outerShared, inner }
inner.js  module.exports = { shared: innerShared }
use.js    const ctrl  = require("./outer").inner   -> ctrl  -> ./outer
          const whole = require("./outer")         -> whole -> ./outer
```
`ctrl` and `whole` recorded IDENTICALLY while denoting different entities; both
modules export `shared`, so resolving `ctrl.shared` returns `outerShared` --
FABRICATED. The fixture removes the naming coincidence masking this on Corpus D.

FIX WAS FEASIBLE (selector recoverable as a 5th column: `local=ctrl
selector=inner` vs `local=whole selector=<none>`), but updating consumers broke
**R14 11/11 -> 4/11** and **R23B 33/33 -> 21/33**. **Reverted rather than
debugged under budget.**

PREREGISTRATION DEFECT: **T2b** ("resolves to INNER's member") is UNSATISFIABLE
within R33's declared scope -- it requires Defect B, which R33 explicitly
excluded. Same class as K1: a preregistered condition quietly depending on
excluded work.

**SEPARATE FINDING — R31 has an UNRECORDED Corpus-B delta.** Module-identity
facts read 48 vs R31's recorded 45, and this SURVIVES the R33 revert, so it is
R31's (I initially misattributed it to R33). The extras are legitimate
object-literal members (`generateSecureToken`, `sendForgotPassword`,
`register` x5). R31 verified STATE FLOWS identical (23) but never checked
module-identity facts. **ACTION: verify against source and amend R31's verdict.**

NEXT: retry R33 with the same fixture, but add the selector as a **SEPARATE
FILE, not a new column** -- `require_bindings.tsv` is read by THREE consumers,
so a column change is a cross-cutting schema edit. **Same coupling failure as
the fixture-directory rule (R26/R27/R29): a shared artifact edited as though it
were local. A new fact belongs in a new file.**

### JS-PROV-R33 RETRY — COMPLETE (Defect A closed)
**JS_PROV_R33=8/8**; all gates green (R07 31/31, R08 13/13, R09 12/12,
R12 28/28, R14 11/11, R17 18/18, R21 13/13, R23B 33/33, R29 9/9);
PROMOTION_GATE=PASS. Report renamed to `js-prov-r33/JS_PROV_R33_VERDICT.md`.

**The one change that mattered:** the first attempt added a 5th column to
`require_bindings.tsv`, which THREE consumers parse -- a cross-cutting schema
edit that broke R14 (11->4) and R23B (33->21). The retry emits the selector to a
**SEPARATE FILE** (`require_member_selection.tsv`); `require_bindings.tsv` stays
byte-compatible at 4 columns and consumers OPT IN.

Teeth all pass, including the shared-name control: `ctrl` never resolves against
`outer.js` and abstains entirely rather than fabricating `outerShared`.
`T2b` (resolve to INNER's member) stays OUT OF SCOPE -- needs Defect B.

```text
CORPUS B  identical on every measure (48 module-identity, 9 validate(), 23 L5
          flows); selector-guarded locals = 0 -- Corpus B has NO
          `require(x).member`, which is exactly why the defect was invisible there
CORPUS D  guard fires on REAL bindings:
            routes/{articles,profiles,tags}-router.js  ctrl -> ../controllers
                                                       selector={articles,profiles,tags}
            controllers/*.js  joinJs -> join-js  selector=default
          L3 28, L5 0 (movement permitted, not required)
```
The false `ctrl -> ../controllers` bindings R32 flagged as latent fabrication are
now REFUSED rather than recorded.

DISCIPLINE: the retry took one structural change -- the one the failure itself
named. **A shared artifact must not be edited as though it were local**, now with
FOUR independent confirmations (R26/R27/R29 fixture dirs, R33 a fact file with
three readers). Also worth noting what the revert bought: the first attempt's
diagnosis was right and its fix worked; only the DELIVERY was wrong. Reverting
cost the implementation but preserved the fixture, the measurement and the named
cause -- and the retry reused all three.

### JS-PROV-R31 AMENDMENT — Corpus-B invariant was incomplete; delta attribution UNRESOLVED
R31 verified Corpus-B **state flows** identical (23) but never checked
**module-identity facts**, which read 48 vs a recorded baseline of 45.

**The +3 is NOT R31's.** Source audit: the facts involved
(`security.util.js:generateSecureToken`,
`services/email/email.service.js:sendForgotPassword`,
`resources/account/*/index.js:register`) all use `exports.X = ...` -- the
NAMED-MEMBER form R14 has handled since it was written. **None of those files
contains an object-literal `module.exports = {...}`**, so R31's member emission
cannot have produced them.

**ATTRIBUTION: UNRESOLVED.** The 45 baseline dates from R14; several revisions
landed between (notably R26 re-export chains). Without the original 45-fact list
it cannot be attributed, and **it has already been misattributed TWICE — first
to R33, then to R31.** Recorded as open rather than guessed a third time.

**SOUNDNESS ESTABLISHED INDEPENDENTLY of attribution:** all 48 facts audited
against source -- every one names a target file that exists and a member that
file demonstrably exports. `verified 48 / not verifiable 0`. The delta is an
ACCOUNTING GAP IN THE RECORD, not a correctness problem in the engine.

**PROCESS DEFECT:** a corpus invariant that checks one layer (flows) and
silently omits another (module identity) will hide real movement. **Corpus
invariants must enumerate the layers they cover.** Same family as K1 (a
preregistered condition that conflated mechanism with count) and R33-T2b (a
tooth depending on excluded work).

## JS-PROV-R34 — Defect B: module-alias export members (characterization)
Report: `docs/corpus-scans/js-prov-r34/`. Nothing implemented.

**Sharper than R32 recorded: the emitted type is WRONG, not merely missing.**
```js
const leaf = require("./leaf");
module.exports = { leaf, ... };
```
```text
emitted:  member=leaf   rhs=barrel.js::program   kind=IDENTIFIER
```
Member `leaf` denotes module `./leaf`; its recorded type is the CONTAINING
file's program scope. **Fifth representation-collapse instance** (R09 receiver
typing, R13 callee identity, R23a isWildcard, R32/R33 require(spec).member).

**Does NOT fabricate today** -- nothing reads a member RHS as a module
reference. Reachable the moment something does; the same was true of Defect A
before the shared-name fixture unmasked it. Fixture deliberately makes it
reachable: `leaf.js` and `other.js` BOTH export `leafFn`, so a guessed join
returns the wrong one.

```text
member    RHS type                     require-bound?  correct disposition
leaf      barrel.js::program (WRONG)   bare            link to ./leaf
sel       (a: ANY) => ANY              SELECTOR        ABSTAIN (R33 guard)
plain     { leafFn: __ecma.Number; }   no              ABSTAIN (not a module)
localFn   barrel.js::program:localFn   no              ALREADY CORRECT today
```
`localFn` is the key constraint: plain-function members already resolve, so the
fix must be conditioned on the REQUIRE BINDING, never on the RHS being an
identifier.

FACTS AVAILABLE for the join: all of them, EXCEPT the RHS identifier NAME on the
member row (the row carries `rhs` as a TYPE, so there is nothing to join against
require_bindings). DELIVERY: new file `export_member_alias.tsv`, **never a new
column** -- module_exports.tsv now has multiple readers (R33's lesson, four
confirmations).

Nominated next: **JS-PROV-R35** with preregistered teeth P1, N1 shared-name
control, N2 selector abstain, N3 non-module abstain, **N4 plain-function member
UNCHANGED**, N5 schema unchanged, **N6 Corpus B identical on ALL ENUMERATED
layers** (module-identity 48, flows 23 -- per the R31 amendment), N7 Corpus D
movement permitted not required, N8 wrong = 0.

DISCIPLINE: R32 called Defect B a coverage gap and Defect A the soundness one.
Right on the evidence then, but incomplete -- B is ALSO a wrong record, just one
nothing currently reads. **The distinction that matters is not "wrong vs
missing" but "wrong and READ" vs "wrong and UNREAD."** A latent wrong record is
a fabrication waiting for its first consumer -- exactly what R30 would have
become had it consulted member RHS types.

## JS-PROV-R35 — module-alias export member identity: Defect B CLOSED
Report: `docs/corpus-scans/js-prov-r35/`. **JS_PROV_R35=11/11**; all gates green
(R07 31/31, R08 13/13, R09 12/12, R12 28/28, R14 11/11, R17 18/18, R21 13/13,
R23B 33/33, R29 9/9, R33 8/8); PROMOTION_GATE=PASS.

`export_member_alias.tsv` -- a **NEW FILE** emitting each object-literal export
member's RHS IDENTIFIER NAME. `module_exports.tsv` unchanged at 7 cols
(R33's lesson, FIFTH confirmation). Resolution gated on the **require binding**,
not on "the RHS is an identifier" -- the condition R34's measurement produced and
that design intuition would have missed.

```text
P1 `module.exports={leaf}` with `leaf=require('./leaf')` -> ./leaf      PASS
N1 SHARED-NAME: leaf.js AND other.js both export `leafFn`, as genuinely
   DIFFERENT declarations -> alias resolves via ./leaf, NEVER other.js  PASS
N2 selector-bearing local abstains (R33 guard)                          PASS
N3 non-module member abstains                                           PASS
N4 plain-function member NOT an alias, still resolves ordinarily        PASS
N5 schema unchanged; alias in a separate file                           PASS
N8 every alias target exists in the export table                        PASS
```
N1 is load-bearing: `other.js` exports `leafFn` as an alias of `otherFn`, so a
guessed link returns a DIFFERENT DECLARATION, not merely a different path.

**CORPUS B identical on ALL ENUMERATED layers** (per the R31 amendment):
L1 48, L3 18, L5 23 all MUST, import-binding 0, validate() 9.

**CORPUS D: the real barrel resolves** -- the one that blocked R30 and R31:
```text
controllers/index.js:{users,tags,profiles,articles}
  -> controllers/{users,tags,profiles,articles}-controller.js
```
Members now carry a correct module link instead of `controllers/index.js::program`
(the containing-file type R34 flagged as a WRONG record).

**NOT YET DONE:** the fact is PRODUCED, not CONSUMED. Corpus D L4/L5 remain 0 --
the R23c/R30 pattern, deliberately a separate revision. Nominated:
**JS-PROV-R36** (consume export_member_alias in callback resolution); note it
ALSO needs R33's selector RESOLVED rather than merely refused, i.e. Defect A's
T2b, still open.

DISCIPLINE: R35 did NOT widen the rule to "RHS is an identifier" -- simpler, and
it would have passed P1. `localFn` shows why: plain-function members already
resolve, and a broader rule would have silently changed correct records.
Chain to get here: R30 -> R31 -> R32 -> R33 -> R34 -> R35, **four of six
producing no downstream movement, each null narrowing the cause.**

## JS-PROV-R36 — selector resolution + consumer integration
Report: `docs/corpus-scans/js-prov-r36/`. **JS_PROV_R36=8/8**; R12 28/28,
R14 11/11, R33 8/8, R35 11/11; Corpus B identical on all five enumerated layers.

**(a) SELECTOR RESOLUTION — Defect A's T2b CLOSED.** R33 REFUSED
`require(spec).member`; R36 RESOLVES it, via R35's alias (so it could not have
been done earlier):
```text
ctrl = require("./outer").inner -> outer.js -> member `inner`
  -> R35 alias (bare require local) -> ./inner
S1 resolves PASS | S2 shared-name: reaches inner.js:innerShared, NEVER
outer.js:outerShared PASS | S3 `.nope` abstains, no outer fallback PASS
S4 bare require not a selector binding PASS
```

**(b) CONSUMER INTEGRATION — C1 ACHIEVED.** On Corpus D,
`routes/{articles,profiles,tags,users}-router.js  ctrl -> the real controller`,
and `ctrl.get -> articles-controller.js::program:get`. This is the chain that
blocked R30, R31, R34 and R35.

**CORPUS D L5 still 0 — but the BLOCKER MOVED, and that is the result:**
```text
                                   before R36   after R36
WRITER_IDENTITY_UNKNOWN_OR_STUB         23          9
WRITE_NO_NEXT_NOT_AVAILABLE_DOWNSTREAM   0         23
```
23 previously-unidentifiable writers are now IDENTIFIED, abstaining for a more
advanced reason: their writes are not before `next()`. **That is CORRECT** --
Corpus D controllers write `ctx.body` and terminate, and R11's next()-boundary
tooth refuses to let a terminal handler's writes reach downstream readers. **Had
R36 produced 23 flows, THAT would have been the bug.**

NEW BLOCKER: the identified callbacks are terminal handlers, not the middleware
writing `ctx.state.user`. **Callback identity is no longer the constraint; chain
membership is.** Nominated: **JS-PROV-R37** — does
`middleware/user-middleware.js` participate in a registered chain the analysis
reaches, and are its writes before next()?

DISCIPLINE: the honest headline is not "still 0" but "**the reason changed, and
the new reason is a rule working correctly rather than a gap**". The
preregistration said movement is not the success criterion; correct resolution
is. The review's chain is now complete on its first two legs — R33 prevented the
collapse, R35 established the alias, R36 resolved the selector and consumed both.

## JS-PROV-R37 — chain membership: characterization (no implementation)
Report: `docs/corpus-scans/js-prov-r37/`. Investigating R36's named blocker.

**NOT a missing fact — a MODEL boundary.** Writer and readers are in DIFFERENT
registration calls:
```text
WRITER   lib/app.js:50       app.use(userMiddleware)            APP-level  (use x13)
READERS  routes/*-router.js  router.get/post/put(..., ctrl.*)   ROUTER-level (get 7/post 6/put 2)
```
The writer's own shape is fine: `ctx.state.user = ...` is BEFORE `next()` and
CONDITIONAL (so R12 would say MAY, correctly).

**R12's refusal is CORRECT AS SPECIFIED.** Its preregistered tooth NEG-2
("different route -> no join", written because a context object is fresh per
request) is the same rule that stops `app.use` joining `router.get`.

**The MODEL is incomplete, not the rule.** Koa's `app.use` middleware runs for
every request BEFORE any router handler mounted on that app — a real semantic
relationship Fable has no upstream/mount relation to express.

WHAT IT WOULD NEED: a **MOUNT RELATION** (router mounted on app) plus an
app-upstream-of-router ordering — a new RELATION, not a new fact.
**PRINCIPAL RISK: a loose mount relation re-enables the cross-route joins NEG-2
exists to forbid** — the exact fabrication class this line has spent thirty
milestones refusing.
CEILING: even if built, Corpus D's write is inside
`if (has(ctx,"state.jwt.sub.id"))`, so any flow is **MAY, never MUST**. Stated
now so a future result is not over-read.

Nominated (if pursued): **JS-PROV-R38 — mount-relation characterization**, whose
teeth MUST include: NEG-2 unchanged (two routers on the same app both writing
the same property still must not join to each other's readers); an unmounted
router receives no middleware; `app.use` registered AFTER the mount does not
flow to it (ORDERING, not co-membership); Corpus B identical on all five layers.

DISCIPLINE: the temptation is to read "R12 refuses a real relationship" as a
defect and relax the scoping. **It is not a defect** — that scoping is what makes
every flow R12 has ever emitted trustworthy. Also: this is the FOURTH distinct
blocker Corpus D produced (L3 direct receiver, callback identity, barrel members,
chain membership), each a different layer, **none found by guessing which layer
was at fault.**

## JS-SOURCE-R02 — WebExtension external messages

Promoted only direct `browser|chrome.runtime.onMessageExternal.addListener`
payload parameter 0, through an inline function or one exact function-valued
local definition. The core preserves the distinct
`WEBEXT_EXTERNAL_MESSAGE_INPUT` kind as MAY. Ordinary `runtime.onMessage`, tabs
events, browser.test, ports, sender metadata, aliases and ambiguous handlers do
not enter this class. Controls: CORE-S05 7/7, JS-SOURCE-R02 10/10, provenance
scanner 4/4. Full contract: `docs/JS_SOURCE_R02_WEBEXT_EXTERNAL_MESSAGES.md`.

## JS-SOURCE-R03 — WebExtension tab URL metadata

Promotes only direct `browser|chrome.tabs.onCreated.addListener` reads of callback
parameter 0's literal `url` field and direct `tabs.onUpdated.addListener` reads of
callback parameter 1/2 literal `url` fields. Each source fact targets the concrete
`STATE_READ`; the whole Tab/changeInfo parameter is never labelled. This keeps
`tab.id`, `tab.cookieStoreId`, `changeInfo.status`, nested `foo.url`, runtime
messages, test/aliased namespaces, and multiply-defined handlers outside the
origin class. `WEBEXT_TAB_URL_INPUT` is MAY-only and a definite same-slot write
kills it. Controls: CORE-S06 6/6 and JS-SOURCE-R03 11/11. Full contract:
`docs/JS_SOURCE_R03_WEBEXT_TAB_URLS.md`. The portable source sidecar is not yet
consumed automatically by the separate property-adjudicator/LLM pipeline; that
class-specific bridge is an explicit next residual, not implied by this gate.
