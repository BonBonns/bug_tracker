# R02 implementation report

Scope per `R02_DECISION.md`'s "Decision 1: R02 source/dataflow scope" -- the 4 capabilities, built
fixture-first against real Joern CPGs, in **new files only**:

- New producer: `tchecker-research-complete/tchecker-property-adjudicator/producers/export_redos_npm_integ_r02.sc`
- New fixtures: `study/redos_npm/r02_fixtures/src/` (12 files) + `raw/` (real frozen R02 output) + `README.md`
- This report.

`export_redos_npm_integ.sc` (R01) was not modified -- confirmed by `diff` against git before and
after this work; only new files were added/edited. `redos_verdict.py`, `adjudicate_js.py`,
`provenance.py`, `staged_enablement.py` were never edited (run read-only for validation only, see
"Downstream verdict interaction" below). `reportable` stays hardcoded `false` everywhere; no
pipeline wiring touched.

## Method

Same discipline as R01's own build: for each capability, a small synthetic fixture was written,
compiled with the SAME `jssrc2cpg.sh` (via `JOERN_HOME=tchecker-research-complete/joern-install/joern-cli`)
into a real CPG, and inspected with throwaway `joern --script` probes (not committed -- scratchpad
only) BEFORE any producer logic was written. All quotes below are real probe output, not
recollected from memory.

## Capability 1: exported class instance-method recognition

**Real CPG evidence** (`export { Context }` on a class with `constructor`, `graphql`, `other`):
```
=== export { Context } desugaring ===
assign code=Context = class_named_export.js::program:Context:<init> line=Some(1)
    arg1: Identifier code=Context
    arg2: MethodRef code=constructor(req) {...}
assign code=exports.Context = Context line=Some(12)
    arg1: Call code=exports.Context
    arg2: Identifier code=Context
```
Confirms named ESM export desugars to EXACTLY the same `Identifier = MethodRef(<init>)` +
`exports.NAME = Identifier` shape as `module.exports = SomeClass` -- no separate ESM path needed,
matching R01's own finding for plain function exports.

```
=== method.typeDecl navigation (for class_named_export.js methods) ===
method=<init> -> typeDecl navigation:
  m.typeDecl = List(class_named_export.js::program:Context)
method=graphql -> typeDecl navigation:
  m.typeDecl = List(class_named_export.js::program:Context)
=== cpg.typeDecl.method for Context ===
Context typeDecl fullName=class_named_export.js::program:Context
  methods: List(<init>, graphql, other)
```
`m.typeDecl` navigates directly from any Method (including `<init>`) to its owning class; `td.method`
lists every method the class owns. **Implementation**: `resolveExportRhs`'s constructor case (was:
unconditional `Left("CLASS_CONSTRUCTOR_NOT_PUBLIC_API")`) now returns `Right(ClassExport(td))`
after a defensive `td.method.name("<init>").l.size > 1` check (capability 5, see below); the
export-assignment loop then registers every OTHER method on `td` (`td.method.filterNot(_.name ==
"<init>")`) as an `ExportedFn` named `$exportName.prototype.$methodName`, while the constructor
itself is still correctly never added as a source (`CLASS_CONSTRUCTOR_NOT_PUBLIC_API`'s own framing
is unchanged -- the constructor is not public API; its *other* methods now are).

**Fixture confirmation**: `class_export_direct.js` (`module.exports = Widget`, `process`/`safe`
methods) -- `process(input)` resolves and reaches its DANGEROUS sink; the constructor is never
promoted. Real emitted row: `sink L10 src=input`.

## Capability 2: object-literal shorthand export recognition

**Real CPG evidence** (`module.exports = { foo, bar }`):
```
assign code=[module.exports = { foo, bar }] line=Some(7)
  arg1: class=Call code=[module.exports]   (fieldAccess)
  arg2: class=Block code=[{ foo, bar }]
    block! children:
      child class=Local code=[_tmp_2]
      child class=Call code=[_tmp_2.foo = foo]
      child class=Call code=[_tmp_2.bar = bar]
      child class=Identifier code=[_tmp_2]
```
And for the computed-key variant (`{ [computedKey]: foo }`):
```
node=Call code=[_tmp_1[computedKey] = foo]
node=Call code=[_tmp_1[computedKey]]     <- <operator>.indexAccess, non-literal key argument
```
Confirms the RHS is a `Block` whose direct children include one `<operator>.assignment` Call PER
property (LHS `<operator>.fieldAccess` with a `FieldIdentifier` naming the property for a normal
property, `<operator>.indexAccess` with a non-literal key for a computed one -- a real, distinct
shape from the top-level `module.exports[computedExpr]` dynamic key R01 already handles).
**Implementation**: `resolveObjectLiteralExport` reads the Block's direct-child assignment Calls;
for a `fieldAccess` LHS it recurses into the EXISTING `resolveExportRhs` on the property's own RHS
expression (reusing the single-prior-assignment identifier rule unchanged) and registers the
property under its own name; for an `indexAccess` LHS it abstains
`COMPUTED_OBJECT_LITERAL_PROPERTY_KEY`, never guessed.

**Fixture confirmation**: `obj_shorthand_export.js` -- both `foo`/`bar` resolve; `foo` (dangerous)
reaches, `bar` (safe) resolves but is never emitted (real row: `sink L5 src=x`).
`obj_shorthand_dynamic_key.js` -- abstains `COMPUTED_OBJECT_LITERAL_PROPERTY_KEY`, zero rows.

## Capability 3: constructor parameter -> exact `this.field` identity -> method-use propagation

**Real CPG evidence** (`this.req = req` in a constructor; `this.req.body` read elsewhere):
```
assign code=[this.req = req]
  arg1: Call code=[this.req]  (fieldAccess: arg1=Identifier "this", arg2=FieldIdentifier "req")
  arg2: Identifier code=[req]
...
node=Call code=[this.req.body]
node=Call code=[this.req]        <- nested fieldAccess, receiver of the outer .body access
```
**Implementation**: `findThisFieldAssigns` collects every `this.FIELD = <rhs>` assignment across
ALL of the exported class's own methods. Per field: more than one assignment site anywhere in the
class -> abstain `REASSIGNED_THIS_FIELD`; the single site not inside `<init>` -> abstain
`NON_CONSTRUCTOR_THIS_FIELD_ASSIGNMENT`; the RHS not EXACTLY an `Identifier` naming one of the
constructor's own parameters -> abstain `COMPUTED_THIS_FIELD_ASSIGNMENT`; the named parameter
itself reassigned inside the constructor before this point -> abstain
`MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER`. Only a field surviving all four checks contributes
`this.FIELD` read-site expressions from the class's OTHER methods to `packageApiSources`, fed into
the same `reachableByFlows` call as everything else.

**A real, load-bearing discovery made while fixture-testing this capability**: this Joern version's
`reachableByFlows` does **not** propagate from a sub-expression to a compound PARENT expression
built directly on top of it in the same statement -- confirmed directly:
```
this.req occurrences found: 1
  this.req call id=30064771078 code=[this.req] line=Some(9)
=== reachableByFlows from this.req (id=30064771078) to sink input (id=30064771077 = "this.req.body") ===
  result size: 0
=== degenerate self-reach check ===
self-flow result size: 1
```
A follow-up probe showed this is **not specific to `this` at all** -- it is a pre-existing property
of the WHOLE R01 base design: a plain exported function parameter does not reach a field access
built on top of it either:
```
function f(x) { return /^(a+)+$/.test(x.foo); }
...
  from identifier x (id=68719476738) -> sink input [x.foo]: flow size=0
```
R01 itself already worked around exactly this for `req`/`message` ingress sources by matching the
FULL compound expression (`req.body`, via `SOURCE_PATTERN`/`MESSAGE_SOURCE_PATTERN` regex on the
expression's own code) as the source directly, rather than relying on flow-through from a bare
`req` identifier -- every "reachable" row R01 ever emitted from an ingress param, and (before this
fix) every row this producer emitted from a bare exported parameter used DIRECTLY as a sink
argument, was a same-node or regex-matched-compound-expression case, never a genuine
child-to-parent structural propagation. Since capability 3 has no fixed vocabulary of field names
to regex-match (the field name is whatever the constructor's own parameter was assigned to), the
fix is structural instead: `collectFieldAccessChain` walks every `<operator>.fieldAccess`/
`<operator>.indexAccess` Call in the same containing method whose receiver argument IS the
previous level's node (`this.req` -> `this.req.body` -> ...), adding EVERY level as its own source
-- the same "match whichever compound shape really appears" principle R01 already used, applied
structurally instead of via a fixed regex.

**Fixture confirmation**: `named_class_export_with_this_field.js` (the velociradix-shaped
`Context`/`graphql()`/`this.req.body` case) -- after the chain fix, `this.req.body` itself is
in the source list and the sink is reached: real row `sink L9 src=this.req.body`.
`this_field_reassigned.js` -- abstains `REASSIGNED_THIS_FIELD`, zero rows.
`this_field_computed.js` -- abstains `COMPUTED_THIS_FIELD_ASSIGNMENT`, zero rows.
`two_exported_classes.js` -- `Alpha`'s `this.a` and `Beta`'s `this.b` both resolve independently
(real rows: `sink L12 src=this.a`, `sink L23 src=this.b`), no cross-class confusion.

## Capability 4: cross-method/closure resolution using lexical/capture identity

**Real CPG evidence** -- `method.astParent`, for a Method declared inside another function's body,
resolves DIRECTLY to the enclosing Method (not a Block or other wrapper):
```
parseM.astParent = METHOD code=:program
=== closure_two_same_name.js nested: useA inside makeA ===
  useA methodRef owning method = closure_two_same_name.js::program:makeA
=== closure_shadow.js nested: inner inside outer ===
  inner methodRef owning method = closure_shadow.js::program:outer
```
And the top-level `:program` Method's own `astParent` is a `TypeDecl` -- confirmed real base case
that terminates the walk:
```
program's astParent class = class io.shiftleft.codepropertygraph.generated.nodes.TypeDecl
```
A critical correctness check: at each scope level, the assignment search must be scoped to THAT
level's own Method (`a.method.fullName == levelMethod.fullName`), not `levelMethod.ast` unscoped --
because `.ast` itself descends into nested-closure subtrees:
```
=== closure_shadow shadowing check: RE assigns visible in 'outer' method's OWN ast ===
  outerM.ast finds: const RE = /^(a+)+$/ line=Some(3) enclosingMethod=closure_shadow.js::program:outer
```
(here it happened to be scoped correctly because `inner` has no RE declaration of its own to
collide with, but the risk -- an unscoped search silently picking up an unrelated inner closure's
own same-named declaration -- is real and is exactly why `closure_cross_scope.js` exists as a
regression fixture: two independent closures, same variable name, must never cross-contaminate).

**Implementation**: `resolvePatternR02` (a renamed, extended copy of `resolvePattern` -- per the
task's own explicit instruction that this ONE Stage-1 helper, not `resolveExportRhs`, is what
capability 4 extends; `classifyPattern`/`NESTED_QUANTIFIER` and the sink-enumeration loop itself
remain byte-for-byte frozen) walks `method.astParent` upward, searching each level's own
scope-local assignments only; more than one live assignment at a level aborts the walk with
`MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER` (abstain, never guess which is live); reaching a
non-Method `astParent` (the module-scope base case) with nothing found aborts with
`UNRESOLVED_IDENTIFIER_NO_ENCLOSING_SCOPE_BINDING`.

**Fixture confirmation**: `closure_cross_scope.js` -- `makeHandlerA`'s own `RE` (dangerous)
resolves and reaches (real row: `sink L9 src=param`); `makeHandlerB`'s own `RE` (safe) resolves
independently to ITS OWN pattern and is correctly never emitted -- no cross-contamination.
`closure_shadow.js` -- resolves to the INNER `RE` (dangerous), not the outer module-scope `RE`
(safe): real row `sink L12 src=param`. Had the bug existed (outer silently picked), this sink would
classify SAFE and emit nothing -- the row's presence IS the proof. `closure_ambiguous_reassignment.js`
-- abstains `MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER` (real stderr:
`resolvePatternR02 ABSTENTIONS (1): RE=MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER`), zero rows.

## Capability 5: explicit abstention for shadowing/reassignment/ambiguity (cross-cutting)

All abstention paths, with the reason string each one emits and where it was fixture-tested:

| Reason string | Capability | Fixture-tested |
|---|---|---|
| `COMPUTED_OBJECT_LITERAL_PROPERTY_KEY` | 2 | `obj_shorthand_dynamic_key.js` |
| `REASSIGNED_THIS_FIELD` | 3 | `this_field_reassigned.js` |
| `NON_CONSTRUCTOR_THIS_FIELD_ASSIGNMENT` | 3 | (real packages only -- see fuse-napi/ssh2 below; no dedicated fixture, real-world-confirmed) |
| `COMPUTED_THIS_FIELD_ASSIGNMENT` | 3 | `this_field_computed.js`, and real: velociradix's own `this._req = new Request(ptr)` |
| `MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER` (constructor-param reassignment variant) | 3 | code path present, exercised transitively by capability 4's own use of the same check (see below) -- no dedicated capability-3 fixture built separately from `this_field_reassigned.js`'s coarser field-level check |
| `MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER` (closure variant) | 4 | `closure_ambiguous_reassignment.js` |
| `UNRESOLVED_IDENTIFIER_NO_ENCLOSING_SCOPE_BINDING` | 4 | real: ssh2/mariasql's own OTHER (non-`RE_HEADER`/`RE_PARAM`) identifiers, see below |
| `MULTIPLE_CANDIDATE_CONSTRUCTORS` (defensive, `td.method.name("<init>").l.size > 1`) | 1 | code path present, **not independently fixture-triggered** -- see honest note below |
| `UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT` (multi-constructor-shaped reassignment) | 1/5 | `multiple_candidate_constructors.js` |
| `DYNAMIC_COMPUTED_EXPORT_KEY` (already-R01 shape, regression-checked under R02) | -- | `dynamic_export_key_top_level.js` |

**Honest note on "multiple candidate constructors"**: the task asked for a fixture where "MULTIPLE
possible constructors for a class ... you can't statically resolve to exactly one" abstains. The
originally-assumed mechanism (two `Identifier = MethodRef(<init>)` assignments to the same
identifier, triggering the EXISTING, reused `AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS`
path) does not actually occur in real js2cpg output: a class DECLARATION's own name binds directly
to its `<init>` MethodRef at the declaration site (`class Widget {} ` desugars to
`Widget = MethodRef(<init>)`), but a LATER reference to that name elsewhere (`let Exported =
Widget`) is `Identifier = Identifier`, not `Identifier = MethodRef` -- confirmed directly by
building `multiple_candidate_constructors.js` both with named class declarations and with
anonymous class EXPRESSIONS (`let Exported = class {...}`) and observing the SAME real abstention
reason both times: `UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT` (zero qualifying candidate
assignments to `Exported` are found, since neither RHS is itself a MethodRef). This is still a
real, correct, tested capability-5 abstention for this exact shape -- it never guesses which class
is "the real" export -- just via a different reason label than originally hypothesized. The
defensive `MULTIPLE_CANDIDATE_CONSTRUCTORS` check (more than one `<init>` owned by the SAME
resolved TypeDecl) remains in the code as defense-in-depth but was not independently triggered by
any constructed fixture, because js2cpg's `methodFullName` is unique per declared constructor in
every real shape tried -- a genuine node-level constructor collision appears effectively
unreachable in practice, not merely untested by omission.

## Regression fixture results (7/7 required, all real, all pass)

| # | Fixture | Result |
|---|---|---|
| 1 | `closure_cross_scope.js` (same-name, different closures) | **PASS** -- independent resolution, no cross-contamination |
| 2 | `closure_shadow.js` (lexical shadowing) | **PASS** -- resolves to inner declaration |
| 3 | `this_field_reassigned.js` (reassigned field) | **PASS** -- abstains, zero rows |
| 4 | `two_exported_classes.js` (two exported classes) | **PASS** -- 4 independent rows, no cross-class confusion |
| 5 | `dynamic_export_key_top_level.js` + `obj_shorthand_dynamic_key.js` (dynamic keys) | **PASS** -- both abstain |
| 6 | `obj_shorthand_export.js` (object shorthand) | **PASS** -- both resolve |
| 7 | `class_export_direct.js` (direct class export) | **PASS** -- other methods resolved, constructor stays non-public |

**Zero regressions, confirmed by direct diff, not by inspection alone.** R01 (frozen, byte-for-byte
unmodified -- confirmed via `git diff` showing no changes to `export_redos_npm_integ.sc`) was rerun
against its OWN original `study/redos_npm/fixtures/src/` and reproduced its documented baseline
exactly: 11 sink targets, 10 DANGEROUS, 7 rows (6 `PACKAGE_API_INPUT` + 1 `APPLICATION_INGRESS`).
R02 was then run over the SAME CPG; a `comm -23` diff of the two `source_facts.tsv` files (every
R01 row, minus every R02 row) is **empty** -- every one of R01's 7 rows is preserved, same sink and
source node ids, same lines. R02 additionally emits exactly 1 new row: `class_export.js`'s own
`check(input)` (R01's own README already documents this file as "ABSTAINED -- resolves to the
class's own `<init>`, not its real public methods") now resolves and reaches -- capability 1 fixing
the exact, pre-documented gap, not a regression. R01 (frozen) was separately run over the NEW R02
fixture set (`r02_fixtures/src/`) as a sanity check that this fixture set genuinely exercises new
territory: 18 sink targets, 12 DANGEROUS (2 fewer than R02's 14, since R01 cannot cross-scope-walk
at all), **0 exported functions resolved, 0 rows emitted** -- confirms none of the 12 R02 fixtures
happen to also work under R01 by coincidence.

## Real-package validation (4 packages, fresh tarballs from npm, real jssrc2cpg + real R02 run)

All 4 built via the same `jssrc2cpg.sh`/`joern --script` invocation `run_pilot25.py` uses
(`JOERN_HOME=tchecker-research-complete/joern-install/joern-cli`), R01 and R02 run back-to-back
against the identical CPG for a clean before/after.

### `velociradix@8.3.1` -- **no promotion; correct, honest abstention, verified against real source**

R01: 1 dangerous sink (`fieldRegex` at `index.mjs:940`), 0 rows. R02: same 1 dangerous sink, still
**0 rows** -- `redos_verdict.py` classification unchanged: `PACKAGE_API_INPUT_REACHABLE: 0` both
before and after, `n_findings: 0` both before and after.

Real source, fetched fresh and inspected directly (`index.mjs:452-455`):
```js
class Context {
  constructor(ptr, appInstance) {
    this._req = new Request(ptr);
    this._reset(ptr, appInstance);
  }
```
`this._req` is set to `new Request(ptr)` -- a CONSTRUCTED value, not an exact, untransformed
identity of the constructor's own parameter. Capability 3's own real, observed stderr output:
```
[r02_velociradix-8.3.1] this-field ABSTENTIONS (32): ... Context.this._req=COMPUTED_THIS_FIELD_ASSIGNMENT ...
```
This directly confirms the R02_DECISION.md's own speculation: "this.req may be set somewhere other
than [an exact passthrough of] the constructor['s own parameter] ... the correct behavior ... is to
ABSTAIN, not guess or force a match." **The honest, verified answer: velociradix's `Context.
graphql()` does NOT promote to a finding, because `this._req` genuinely is not an exact
constructor-parameter identity -- this is the correct outcome, not a bug.** (A second, independent,
real complication -- not needed to reach this conclusion, but worth recording: the real sink's
actual input, `query`, is reached only after `this.req` -> a getter -> `.body` -> `JSON.parse(...)`
-> `.query` -- several transformation hops beyond a single field-access chain, and JSON.parse is a
call boundary this dataflow engine has no special modeling for; even a hypothetical exact-identity
`this._req` would very likely still not reach through that chain, though this was not independently
tested since capability 3 already, correctly, abstains at the very first hop.)

### `fuse-napi@2.3.1` -- object-literal export now resolves exactly as expected; does not become a new pipeline finding

R01: 2 dangerous sinks, 0 rows (`module.exports = { MACFUSE_URL, wrapMacFuseLoadError }` abstained
as `UNRESOLVED_RHS_SHAPE`, per its own already-documented gap). R02: same 2 dangerous sinks,
**2 rows emitted** for the `lib/macfuse.js:5` sink (`wrapMacFuseLoadError`'s own `err` parameter,
via the ordinary `const message = err && err.message ? err.message : String(err)` assignment-flow,
reaching `/(?:macfuse|libfuse3(?:\.\d+)*\.dylib)/i.test(message)`). Real stderr:
```
[r02_fuse-napi-2.3.1] EMIT sink=30064776961(L5) src=68719482777(L4:err) family=PACKAGE_API_INPUT
  note=pattern=/(?:macfuse|libfuse3(?:\.\d+)*\.dylib)/i classification=DANGEROUS ...
[r02_fuse-napi-2.3.1] EMIT sink=30064776961(L5) src=68719482780(L4:err) family=PACKAGE_API_INPUT ...
```
`redos_verdict.py`'s own raw classification (reading `source_facts.tsv` directly, independent of
the adjudicator) shows `SINKS_WITH_ANY_ESTABLISHED_SOURCE: 1` under R02 (was 0 under R01) --
capability 2 mechanically resolved exactly the shape the decision record named. **This does NOT
promote to a `PACKAGE_API_INPUT_REACHABLE` pipeline finding**: `redos_verdict.py`'s
`PACKAGE_API_INPUT_REACHABLE` count stays `0` under R02 too, because the downstream
`adjudicate_js.py` (never modified here) crashes on this specific case --
`IndexError: list index out of range` at `srcf[0][0]` in `build_evidence_v0()` -- a real,
pre-existing bug in that unmodified script, triggered (not caused) by this sink now legitimately
having 2 source rows instead of 0 or 1 (both rows point at the SAME sink from 2 different real
`err` identifier occurrences in the ternary, matching R01's own established one-row-per-flow-path
convention). This is disclosed here, not fixed (per the explicit instruction not to touch
`adjudicate_js.py`/`redos_verdict.py`). Consistent with the categorization doc's own expectation:
this package's OTHER, independent reachability blocker (`INTERNAL_UNDER_PACKAGE_API_MODEL` -- no
`package.json` `"exports"` subpath exposes `./lib/macfuse`, real entrypoint never re-exports it)
still applies regardless of the export-shape fix, so no NEW real-world candidate results here
either way -- exactly as the task's own expectation predicted.

### `ssh2@1.17.0` -- `RE_HEADER` now resolves and classifies DANGEROUS; still correctly zero findings

R01: 0 dangerous sinks (`RE_HEADER` abstains `UNRESOLVED_IDENTIFIER`, never reaches
`classifyPattern`). R02: **1 dangerous sink** -- direct debug-instrumented confirmation:
```
[DEBUG_DANGEROUS_SINK] L1242 call=RE_HEADER.exec(body) resKind=VARIABLE_TO_LITERAL
  resText=/^([\x21-\x39\x3B-\x7E]{1,64}): ((?:[^\\]*\\\r?\n)*[^\r\n]+)\r?\n/gm
  note=nested quantifier: ^([\x21-\x39\x3B-\x7E]{1,64}): ((?:[^\\]*\\\r?\n)*[^\r\n]+)\r?\n
```
-- exactly the real pattern text `COMPLEXITY_ONLY_CATEGORIZATION.md`'s sibling audit already
quoted from `keyParser.js:1231`, now correctly resolved via capability 4's `astParent` walk instead
of abstaining. **Real, honest result: `rows=0`, `redos_verdict.py`'s `PACKAGE_API_INPUT_REACHABLE`
stays 0, `n_findings: 0` both before and after.** Root cause, verified directly: `RE_HEADER`'s
consumer, `RFC4716_Public.parse = (str) => {...}` (`keyParser.js:1233`), is neither an ES6 class
instance method (capability 1's own scope) nor an object-literal-shorthand export (capability 2's
own scope) -- it is a bare STATIC property assignment on a plain object (`RFC4716_Public.parse =
...`), a third, genuinely different shape outside all 4 R02 capabilities' scope. `str`/`body` is
therefore never enumerated as a PACKAGE_API_INPUT source at all, regardless of the pattern now
resolving correctly. **This is the honest, complete answer: ssh2 does NOT become pilot25's second
real candidate under R02** -- the pattern-resolution gap capability 4 targeted is fixed exactly as
scoped, but a distinct, out-of-scope export-recognition gap (static-property-assignment methods)
independently blocks promotion.

### `mariasql@0.2.6` -- `RE_PARAM` now resolves and classifies DANGEROUS; same honest zero-finding outcome, same reason shape

R01: 0 dangerous sinks. R02: **2 dangerous sinks** (both `RE_PARAM.exec(query)` call sites),
directly confirmed:
```
[DEBUG_DANGEROUS_SINK] L302 call=RE_PARAM.exec(query) resKind=VARIABLE_TO_LITERAL
  resText=/(?:\?)|(?::(\d+|(?:[a-zA-Z][a-zA-Z0-9_]*)))/g
  note=quantifier followed by more content in alternation branch: (?::(\d+|(?:[a-zA-Z][a-zA-Z0-9_]*)))
[DEBUG_DANGEROUS_SINK] L352 call=RE_PARAM.exec(query) resKind=VARIABLE_TO_LITERAL ... (same pattern)
```
-- matching `REMAINING_SIX_NO_COMPLEXITY_CANDIDATE.md`'s own quoted real pattern from
`lib/Client.js:18` exactly. **Real, honest result: `rows=0`, `PACKAGE_API_INPUT_REACHABLE` stays 0,
`n_findings: 0` both before and after.** Root cause, verified directly against real source
(`lib/Client.js:28` and `:296`):
```js
function Client(config) { ... }              // ES5 constructor FUNCTION, not an ES6 `class`
...
Client.prototype.prepare = function(query) {  // classic ES5 prototype-assignment instance method
```
`Client` resolves as a plain `SingleFunction` (confirmed: R01's own stderr already showed
`module.exports@Client`, unchanged under R02), never as a `ClassExport`, because js2cpg's `<init>`-
based class recognition (capability 1's own trigger) is an ES6-`class`-specific shape --
`Client.prototype.prepare = function(){}` is a real, distinct, genuinely different (and
out-of-scope) export pattern from the ES6 `class` body method capability 1 targets. `prepare`'s own
`query` parameter is therefore never enumerated as a PACKAGE_API_INPUT source. **Same honest
conclusion as ssh2: the pattern-resolution gap is fixed exactly as scoped; mariasql does NOT become
a real candidate under R02**, blocked by a distinct, disclosed, out-of-scope export-shape gap
(ES5 prototype-assignment instance methods) rather than the capability-4 gap this pilot originally
flagged for it.

## Summary: does either ssh2 or mariasql become pilot25's second real candidate?

**No, for neither package, and this is a directly-verified, honest "no."** Capability 4 (the
specific gap `R02_DECISION.md` scoped in for both packages) works exactly as designed for both:
`RE_HEADER` and `RE_PARAM` now correctly resolve via the real lexical/closure-scope walk and
correctly classify DANGEROUS under the frozen, untouched `classifyPattern`. Neither promotes to a
`PACKAGE_API_INPUT_REACHABLE` finding, because in BOTH real packages the method that actually
consumes the now-resolved regex is exported via a shape none of the 4 scoped R02 capabilities
covers (a bare static-property-assignment method for ssh2, an ES5 prototype-assignment instance
method for mariasql) -- real, disclosed, independently-verified boundaries of this R02 pass's own
scope, not bugs, and not silently claimed as findings that the evidence does not support.

## Downstream verdict interaction (disclosed, not fixed)

Running `redos_verdict.py` (read-only, unmodified) against the R02 raw output surfaced one
pre-existing bug in `adjudicate_js.py` (also unmodified): a sink with more than one
`PACKAGE_API_INPUT` source row (fuse-napi's `wrapMacFuseLoadError` case, 2 rows for the same sink)
causes `build_evidence_v0()` to crash with `IndexError: list index out of range` at `srcf[0][0]`.
Disclosed here per the "if you find ANY regression, do not hide it" instruction, even though this
is not itself a regression in anything R02 changed (R01 was simply never exercised with >1
PACKAGE_API_INPUT row for the same sink before) and is explicitly out of scope to fix
(`adjudicate_js.py` is one of the files this task says not to touch).
