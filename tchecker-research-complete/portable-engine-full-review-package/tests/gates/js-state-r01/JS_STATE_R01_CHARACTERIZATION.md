# JS-STATE-R01 — Failure-State Erasure Characterization

**Status: characterization only. No detector was implemented. Nothing here is a
verdict.** This measures whether real Joern `jssrc2cpg` output gives the portable
engine enough to *represent* the target bug shape, per the instructions.

Real frontend used throughout: joern-cli, `codepropertygraph-domain-classes 1.7.70`
(the same install verified for JSTS-R01/Gate 24/24-TS). All facts below came from
actually running `jssrc2cpg` + `joern` against the fixture and reading the raw CPG
output — none of this is inferred from documentation or memory. Raw TSV/log
evidence is archived under `evidence/`.

**Revision note:** this report was revised once after the initial pass closed out
three items the first pass had explicitly flagged as open (`String`/`Boolean`/
`parseInt` unverified-by-analogy; a shallow-AST-walk bug in the guard-subject
query that silently dropped case3). Both are now closed and empirically verified;
see Q2 and Q3 below for what changed and why. `parseFloat()` remains unexercised
(one case short of full closure) and is called out explicitly rather than quietly
dropped.

## Target bug shape (recap)

```text
callee returns SUCCESS_VALUE | ERROR_VALUE
  -> caller transforms/coerces the result
  -> transformation destroys the failure discriminator
  -> caller checks the TRANSFORMED value for failure
  -> execution continues down a security-sensitive success path
```

## Fixture

`fixture/state_erasure.ts` — see file. Contains the two required motivating cases
(`case1_safeGuardBeforeTransform`, `case2_transformBeforeGuard`) plus: a
discriminated-union safe case, a `null | number` case (safe and erased variants),
a provably-preserving transform, a provably-unknown transform, an
erasure-that-never-reaches-a-sink case, bitwise/unary-coercion variants of the
core shape, and `String()`/`Boolean()`/`parseInt()` variants added in a follow-up
pass to close an initially-unverified gap (see Q2). 13 case functions total
(including the `case4b` null-erasure variant).
`authenticate()` is `declare`d only (no body) on purpose, to test whether the
sink shape can be recognized without seeing sink internals.

## Q1 — Can the frontend establish distinct success/failure return states?

**Partially, with a specific and reproducible gap.**

- Plain TS union return (`function create(ok): Result` where `type Result = number
  | Error`): `method_returns.tsv` reports `methodReturn.typeFullName = "Result"` —
  the **alias name**, not the expanded union. However, the structural union
  string `"number | Error"` *does* exist elsewhere in the CPG's type table
  (`type_decls.tsv`, id `167503724571`, `is_external=true`), just not attached to
  `create`'s `methodReturn`. So the structural fact exists in the graph but a
  normalizer would need a second lookup (alias name -> matching type-table entry)
  to recover it; it is not handed over in one step. Evidence:
  `evidence/standard_export_raw/method_returns.tsv` row for `create`,
  `evidence/standard_export_raw/type_decls.tsv` row 167503724571.

- Discriminated union (`DResult = {ok:true,...} | {ok:false,...}`):
  `methodReturn.typeFullName = "DResult"` (alias name again), and `DResult`'s own
  `type_decls.tsv` entry is an external stub with **no member breakdown** — unlike
  a named `interface`/`class` (which Gate 24-TS already showed *does* get member
  facts). The two variant shapes of the union are not structurally decomposed
  anywhere in the export. A frontend can see that `r3.ok` is a field access
  (`<operator>.fieldAccess`), but cannot currently learn from type facts alone
  that `ok` is a boolean discriminant with two possible shapes behind it.

- `null | number` return (`createN`): this is the most concerning finding.
  `method_returns.tsv` reports `methodReturn.typeFullName =
  "__ecma.Boolean:<operator>.conditional:<returnValue>"` — a malformed,
  internal-looking type-recovery artifact, not `"number | null"` or even `"ANY"`.
  The correct structural type (`"number | __ecma.Null"`) does independently exist
  in the type table (`type_decls.tsv` id `167503724572`), exactly as with `Result`
  above, but the method's own declared return type is actively **wrong**, not just
  imprecise. This reproduces on a plain `ok ? 11 : null` ternary with no naming
  tricks involved — it looks like a real Joern JS/TS type-recovery bug for
  ternary-typed returns, not a fixture artifact. Evidence:
  `evidence/standard_export_raw/method_returns.tsv` row `107374182403`.

- `Error`/custom-error object returns: `new Error(...)` lowers to
  `<operator>.alloc` plus a constructor call; the returned value's type is
  recoverable (`ErrorConstructor` appears in the type table). This part works.

**Conclusion for Q1:** return-state visibility is real but indirect for union
aliases (needs a second type-table lookup) and actively broken for at least one
concrete pattern (ternary-typed nullable return). Discriminated-union member
shapes are not structurally exposed at all; only the field-access pattern used
against them is visible.

## Q2 — Can transformations that may erase the distinction be represented?

**Yes, cleanly, for every requested transformation, empirically verified (not
inferred).**

| Transformation | CPG representation | Verified how |
|---|---|---|
| `Number(x)` | `CALL` name=`Number`, `dispatchType=STATIC_DISPATCH`, resolves to an external stub `METHOD` (`is_external=true`, `full_name="Number"`, `ast_parent_type=NAMESPACE_BLOCK`, `ast_parent_full_name=<global>`) | `evidence/characterize_raw/coercion_calls.tsv`, `evidence/standard_export_raw/methods.tsv` |
| unary `+x` | `<operator>.plus` CALL with **one** argument | `case9`, `evidence/characterize_raw/coercion_calls.tsv` |
| `x \| 0` (bitwise) | `<operator>.or` CALL, two arguments | `case8`, same file. Distinct from unary/binary `+`; distinct from `<operator>.logicalOr` (not tested here but structurally a different operator name from `\|\|` by construction) |
| template/string coercion `` `${x}` `` | `<operator>.formatString(...)` CALL, the interpolated value as an argument alongside literal string parts | separate probe, `/tmp/tmpl_check` (not archived in this package; reproducible by adding a template literal to the fixture — see "reproduction note" below) |
| `String(x)`, `Boolean(x)`, `parseInt(x)` | **Empirically verified** (extended fixture, cases 10–12): identical shape to `Number(x)` — `CALL`/`STATIC_DISPATCH`, external stub `METHOD` with `is_external=true`, `ast_parent_type=NAMESPACE_BLOCK`, `ast_parent_full_name=<global>`. `parseInt` additionally carries its radix as argument 2, same `arguments.tsv` shape as any other call. `parseFloat` was not exercised in the fixture but is structurally identical by the same mechanism (bare global function call) — this one remaining case is genuinely just unexercised, not unverified-by-mechanism. |
| user-defined normalizer (`externalNormalize`) | `CALL` name=`externalNormalize`, resolves to an external stub (`is_external=true`) **indistinguishable at the `is_external` level from a real language builtin** | `case6`, same file |

**Important subtlety for R02:** `is_external=true` alone cannot distinguish "known
ECMAScript coercion builtin" from "arbitrary undeclared external function" —
`Number` and `externalNormalize` both show up as external stubs with the same
shape. Telling them apart requires matching the callee's `full_name` against a
small, fixed, spec-defined set (`Number`, `String`, `Boolean`, `parseInt`,
`parseFloat`, plus the coercion operators `<operator>.plus`(unary),
`<operator>.or`, `<operator>.cast` to a numeric type, `<operator>.formatString`).
**This is not the kind of name-based inference the hard rule prohibits** — it is
recognizing fixed language/runtime identifiers with spec-defined semantics, the
same way `<operator>.instanceOf` is recognized by its canonical CPG operator name.
The hard rule is about not trusting *programmer-chosen* identifiers (variable
names, user function names) as evidence of behavior; matching a closed set of
language builtins is categorically different and should be treated as safe to do.

## Q3 — Can we prove whether the guard checks the original or a transformed value?

**Yes, soundly, via the REF graph — not via identifier name matching.**

A dedicated query (`ref_based_guard_subject.sc`) resolved every guard condition's
checked identifier to its `LOCAL` node via the CPG's `REF` edge (identifier ->
local), and separately resolved every local's producing `CALL` via the same
REF-based path from assignment LHS identifiers — with **no string comparison of
identifier names anywhere in the query**. Result
(`evidence/characterize_raw/ref_based_guard_subject.tsv`):

| Case | Guard's checked LOCAL was produced by | GUARD_SUBJECT |
|---|---|---|
| case1 | `create(flag)` | ORIGINAL |
| case2 | `Number(r2)` | TRANSFORMED |
| case4 | `createN(flag)` | ORIGINAL |
| case4b | `Number(r4b)` | TRANSFORMED |
| case5 | `identity(r5)` | TRANSFORMED (but transform preserves — see Q4) |
| case6 | `externalNormalize(r6)` | TRANSFORMED |
| case7 | `Number(r7)` | TRANSFORMED |
| case8 | `<operator>.or(...)` | TRANSFORMED |
| case9 | `<operator>.plus(...)` | TRANSFORMED |

This exactly separates case1 (checks original) from case2 (checks transformed)
using only REF edges, confirming the core mechanism the bug family depends on is
representable without touching names.

**Gap found in my own query, not in Joern — fixed.** The first version of this
query only walked the condition's *direct* AST children for identifiers; `!r3.ok`
is `<operator>.logicalNot(<operator>.fieldAccess(r3, ok))`, so the checked
identifier (`r3`) is two levels down, not a direct child, and case3 didn't appear
in the table above. Fixed by switching to a full AST-descendant walk
(`cond.ast.isIdentifier` instead of `cond.astChildren`). Re-running confirmed
`case3`'s guard identifier resolves via REF to the same LOCAL that `createD(flag)`
was assigned into — i.e. **GUARD_SUBJECT: ORIGINAL**, same as case1/case4, now
with the same soundness guarantee (REF-based, no name comparison) as every other
case. This was a real query-depth bug on my part, not evidence that Joern lacks
the fact — `control_structures.tsv` always had the correct condition code
(`"!r3.ok"`); the identifier just needed a deeper walk to reach.

## Q4 — Can Fable determine whether a transformation preserves or destroys the discriminator?

**Yes for three separate, principled reasons — and the three reasons matter
because they generalize differently to R02:**

1. **Spec-fixed builtin semantics (ERASES).** `Number`, unary `+`, `x | 0` applied
   to an `Error`-shaped or `null` operand have fixed ECMAScript semantics
   (`ToNumber`/`ToInt32` abstract operations) that are independent of *this*
   program's code — they can be hard-coded as ERASES once, from the language
   spec, and applied wherever the callee matches the closed builtin set from Q2.
   This is what makes case2, case4b, case7, case8, case9 all ERASES.

2. **Structural passthrough (PRESERVES), provable from the callee's own body, not
   its name.** `identity(x) { return x; }` preserves the discriminator not
   because it is *named* "identity" but because its body is a single `RETURN`
   whose returned value's REF resolves directly to the function's own parameter,
   with no `CALL`/operator node in between. This is checkable today with the
   existing `returns.tsv` + `parameters.tsv` + identifier `REF` exports — no new
   fact type is required, just a small structural check ("does this function's
   only return path return its parameter unmodified"). Confirmed by inspecting
   `case5_preservingTransform`'s call chain and `identity`'s own method body in
   `evidence/standard_export_raw/returns.tsv` / `locals.tsv`.

3. **No provable relationship (UNKNOWN -> must abstain).** `externalNormalize` is
   `declare`d only; there is no method body to inspect (`is_external=true`, no
   `returns.tsv` entries for it in this CPG at all — it has no AST). Its
   `full_name` does not match the closed builtin set from Q2. Nothing in the
   exported facts lets Fable assert ERASES or PRESERVES, so the only sound
   answer is UNKNOWN/abstain. This is case6.

**What is missing for a real R02 implementation:** none of reasons 1–3 above are
currently computed by any existing normalizer or core Java type — they were all
manually reconstructed in this session from raw CPG facts. A `TransformationFact`
(per the target schema) would need a small, explicit, versioned table mapping
{closed builtin callee set} -> ERASES/PRESERVES per source-type-class, plus the
structural-passthrough check for user-defined functions, plus explicit UNKNOWN as
the default for everything else. This is exactly item 8 in
`CURRENT_CONCERNS_AND_OPEN_WORK.md` ("security policy should remain downstream")
in miniature: the *classification* of a specific builtin as ERASES is a policy
fact about the language, not something the neutral core should be trusted to
guess generically.

## Q5 — Can the resulting value reach a security-sensitive action?

**Reachability itself: yes, trivially — `authenticate(id2)` is a `CALL` whose
argument is the identifier whose REF resolves to the guarded local, exactly the
same REF mechanism used for Q3.** This needs no new fact type.

**Whether that specific callee counts as "security-sensitive": no, not from the
neutral core alone, and this should not be attempted there.** `authenticate` here
is `declare`d with no body; nothing in its exported facts marks it as
identity/auth/session/token-related beyond its *name*, and the name is exactly
the kind of programmer-chosen identifier the hard rule says not to trust. Case 7
was built specifically to test this: `unrelatedSink(id7)` gets the *same* erased
value as case2's `authenticate(id2)`, and the CPG facts for the two calls are
structurally identical (external stub `CALL`, one argument, REF-traceable to the
transformed local). The only way to tell them apart is an out-of-band
security-sensitive-sink profile (a curated list, injected downstream — same
pattern as Gate 30's context/effect profiles), not anything derivable from this
fixture's CPG facts.

## Per-case report

```text
case1_safeGuardBeforeTransform
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error (class identity)
TRANSFORMATION_VISIBLE: YES (Number(r1), but AFTER the guard)
TRANSFORMATION_SEMANTICS: N/A (transformation occurs after the guard; does not affect guard validity)
GUARD_SUBJECT: ORIGINAL
SECURITY_SENSITIVE_USE: YES (reachable; sink-classification itself is a profile question, not a core fact)
RESULT: SAFE_SHAPE

case2_transformBeforeGuard
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (Number(r2))
TRANSFORMATION_SEMANTICS: ERASES (spec-fixed: Number(Error-shaped object) is never instanceof Error)
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: YES
RESULT: FAILURE_STATE_ERASURE_SHAPE

case3_discriminatedUnionSafe
RETURN_STATE_VISIBLE: YES, with caveat (alias name only; variant shapes not structurally decomposed)
FAILURE_DISCRIMINATOR: r3.ok boolean tag (field access)
TRANSFORMATION_VISIBLE: N/A (no transformation call present)
TRANSFORMATION_SEMANTICS: N/A
GUARD_SUBJECT: ORIGINAL (confirmed via the REF-based query after the case3 AST-walk-depth fix -- see Q3)
SECURITY_SENSITIVE_USE: YES
RESULT: SAFE_SHAPE

case4_nullSentinelSafe
RETURN_STATE_VISIBLE: YES, with caveat (createN's own methodReturn type fact is malformed -- see Q1; correct structural type exists elsewhere in the type table)
FAILURE_DISCRIMINATOR: r4 === null (strict equality)
TRANSFORMATION_VISIBLE: N/A
TRANSFORMATION_SEMANTICS: N/A
GUARD_SUBJECT: ORIGINAL
SECURITY_SENSITIVE_USE: YES
RESULT: SAFE_SHAPE

case4b_nullSentinelErasedByCoercion
RETURN_STATE_VISIBLE: YES, with same caveat as case4
FAILURE_DISCRIMINATOR: strict-equality-to-null
TRANSFORMATION_VISIBLE: YES (Number(r4b))
TRANSFORMATION_SEMANTICS: ERASES (spec-fixed: Number(null) === 0, never null)
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: YES
RESULT: FAILURE_STATE_ERASURE_SHAPE

case5_preservingTransform
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (identity(r5), EXACT-resolved to a local, inspectable function)
TRANSFORMATION_SEMANTICS: PRESERVES (structural passthrough proof, not name-based -- see Q4 reason 2)
GUARD_SUBJECT: TRANSFORMED (but harmlessly -- the transform is provably PRESERVES)
SECURITY_SENSITIVE_USE: YES
RESULT: SAFE_SHAPE

case6_unknownTransformAbstain
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: N/A for this guard (guard is id6 < 0, unrelated to the Error/number discriminator of create()'s result)
TRANSFORMATION_VISIBLE: YES (externalNormalize(r6) is visible as a CALL; its body is not)
TRANSFORMATION_SEMANTICS: UNKNOWN (declared-only external function, not in the closed builtin set)
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: YES
RESULT: ABSTAIN

case7_erasedButNoSensitiveSink
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (Number(r7))
TRANSFORMATION_SEMANTICS: ERASES
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: NO (by fixture construction / sink-profile classification, not a core-provable fact)
RESULT: NOT_APPLICABLE -- erasure is real but the reachable use is not security-sensitive; this does not
        fit SAFE_SHAPE (the discriminator genuinely was destroyed) or FAILURE_STATE_ERASURE_SHAPE (the bug
        definition requires reaching a security-sensitive path) or ABSTAIN (nothing is actually unknown
        here). See "vocabulary gap" below.

case8_bitwiseCoercionBeforeGuard
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (<operator>.or, binary, second operand literal 0)
TRANSFORMATION_SEMANTICS: ERASES (spec-fixed: ToInt32 on an Error-shaped operand is never instanceof Error afterward)
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: YES
RESULT: FAILURE_STATE_ERASURE_SHAPE

case9_unaryPlusBeforeGuard
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (<operator>.plus, ONE argument -- must be distinguished from binary + by arity, not name)
TRANSFORMATION_SEMANTICS: ERASES (spec-fixed: unary + triggers ToNumber, same as Number())
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: YES
RESULT: FAILURE_STATE_ERASURE_SHAPE

case10_stringCoercionBeforeGuard
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (String(r10) -- empirically verified, same external-stub shape as Number)
TRANSFORMATION_SEMANTICS: ERASES (spec-fixed: String(errorObj) calls its .toString(), producing a plain string, never instanceof Error)
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: NO (routed to unrelatedSink on purpose, to keep this case's RESULT distinct from case2/case8/case9 -- see NOT_APPLICABLE note under case7)
RESULT: NOT_APPLICABLE (erasure confirmed; sink not security-sensitive -- same vocabulary gap as case7)

case11_booleanCoercionBeforeGuard
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (Boolean(r11) -- empirically verified)
TRANSFORMATION_SEMANTICS: ERASES (spec-fixed: Boolean(any object, including Error) is always `true`, a primitive boolean, never instanceof Error)
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: NO (routed to unrelatedSink; same reason as case10)
RESULT: NOT_APPLICABLE

case12_parseIntCoercionBeforeGuard
RETURN_STATE_VISIBLE: YES
FAILURE_DISCRIMINATOR: instanceof Error
TRANSFORMATION_VISIBLE: YES (parseInt(r12, 10) -- empirically verified; radix argument confirmed present as a second, distinct argument, same arguments.tsv shape as any other call)
TRANSFORMATION_SEMANTICS: ERASES (spec-fixed: parseInt on a non-string-shaped operand coerces via ToString first, then parses; result is a plain number or NaN, never instanceof Error)
GUARD_SUBJECT: TRANSFORMED
SECURITY_SENSITIVE_USE: NO (routed to unrelatedSink; same reason as case10)
RESULT: NOT_APPLICABLE
```

### Vocabulary gap found while filling this out

The requested three-state `RESULT` vocabulary (`SAFE_SHAPE | FAILURE_STATE_ERASURE_SHAPE
| ABSTAIN`) does not have a slot for case7: erasure is real and provable, but the
destination is not security-sensitive. Calling it `SAFE_SHAPE` would be false (the
discriminator really was destroyed). Calling it `FAILURE_STATE_ERASURE_SHAPE` would
contradict the bug definition, which requires a security-sensitive success path.
Calling it `ABSTAIN` is also wrong — nothing is actually uncertain. **Recommend a
fourth bucket for R02** (e.g. `ERASURE_NOT_SECURITY_RELEVANT`) so the eventual
`SecuritySensitiveUseFact` can carry `NO` as a first-class, non-abstaining answer
without forcing the overall verdict into one of the other three buckets.

## 1. Exact evidence the frontend already exposes

- Method/parameter/return TYPE facts (`methods.tsv`, `parameters.tsv`,
  `method_returns.tsv`), including alias names for union return types and a
  separate type-table entry for the expanded structural union string.
- Call facts with resolvable callee identity, dispatch type, and `is_external`
  (`calls.tsv` + `methods.tsv`), sufficient to identify both user-defined
  transformation functions (inspectable) and external ones (opaque).
- `<operator>.instanceOf`, `<operator>.equals`/`notEquals`, `<operator>.lessThan`,
  `<operator>.logicalNot`, `<operator>.plus`, `<operator>.or`, `<operator>.cast`,
  and `<operator>.formatString` as distinctly-named CALL nodes — every coercion
  and every guard-comparison form asked about in the spec is representable as a
  distinctly identifiable node kind.
- `CONTROL_STRUCTURE` (`if`) nodes with full condition sub-AST and code text
  (via `cpg.controlStructure`, not currently exported by the standing
  `export_ts_facts.sc` — added here as a characterization-only query).
- `REF` edges from identifier nodes to `LOCAL`/`PARAMETER` nodes, which is enough
  to trace guard-subject identity back to its producing `CALL` **without using
  any identifier name as evidence** (Q3).
- `RETURN` facts (`returns.tsv`) sufficient to structurally prove a
  passthrough/preserving transformation from a function's own body.

## 2. Missing facts

- No exported CONTROL_STRUCTURE/condition facts in the standing pipeline
  (`export_ts_facts.sc`) at all — Gate 24-TS and JSTS-R01..R05 never needed `if`
  conditions, so this was never captured. R02 would need to add this as a first-
  class export (a `characterize.sc`-style addition, promoted into the real
  pipeline), not just an ad-hoc query.
- No closed-set builtin-coercion classification table exists anywhere in the
  codebase yet (`Number`/`String`/`Boolean`/`parseInt`/`parseFloat` + coercion
  operators -> ERASES for non-numeric-shaped inputs). This is genuinely new
  policy, matching the shape of `core/effects/`'s transformation-adequacy model
  but for a different effect class (failure-discriminator preservation, not
  sanitization). All five builtins are now confirmed structurally identical
  (`is_external=true`, `<global>` namespace parent), so this table is a short,
  flat list, not a per-builtin special case.
- No structural-passthrough-function detector exists yet (Q4 reason 2) — the
  underlying facts (`returns.tsv`, `parameters.tsv`, identifier `REF`) are
  sufficient, but nothing currently walks them for this purpose.
- No security-sensitive-sink profile exists for JS/TS at all (Q5) — this mirrors
  the C++ track's `SINK-R01`/`SOURCE-R02`, which do have a profile-classification
  layer; JS/TS has no equivalent yet. Cases 7/10/11/12 all needed this gap to be
  worked around by fixture construction (routing to `unrelatedSink`) rather than
  anything Fable itself can currently decide.
- `parseFloat()` specifically was not exercised in the fixture (only reasoned
  about by structural analogy to the four builtins that were verified) — a
  one-line fixture addition away from being closed, but left open here.

## 3. False-positive risks

- **Alias-name return types (`Result`, `DResult`) require a second type-table
  lookup to recover structure; if that lookup is skipped or done wrong, a
  detector could either miss real union returns or, worse, mis-pair an alias
  name with the wrong structural entry in a larger program with many aliases
  sharing partial name overlap.** This needs a precise, ID-based join, not a
  string match on the alias name.
- **The malformed `createN` return-type string is a trap**: a naive detector
  that pattern-matches `typeFullName` for `"null"` or `"| null"` would silently
  miss this exact case, even though the correct structural type exists elsewhere
  in the graph. A real implementation must not trust `methodReturn.typeFullName`
  alone for null-sentinel detection without a fallback path.
- **`<operator>.plus` collision**: unary coercion `+x` and binary addition `a + b`
  share one operator name; a detector that keys off name alone (rather than
  argument count) will misclassify ordinary addition as a coercion, or vice
  versa on multi-argument calls that happen to have one meaningful operand.
- **`is_external=true` is not sufficient evidence of "known coercion behavior"**
  (Q2) — treating any external call as ERASES/PRESERVES without checking against
  the closed builtin set would be unsound in both directions: it would wrongly
  credit unknown external calls with proven semantics, or wrongly treat known
  builtins as unknown if the closed-set check is missing.
- **Security-sensitive-sink classification is out of scope for the core** and
  must come from a downstream profile; a detector that guesses sink-sensitivity
  from a callee's *name* (`authenticate` vs `unrelatedSink`) would violate the
  hard rule directly and would have been fooled by case7 if it had tried.

## 4. Is this bug family worth an R02 implementation?

**Yes, conditionally.** The representational building blocks all exist or are
cheap, well-understood additions (condition export, a small closed-set builtin
table, a passthrough-function check, REF-based guard-subject resolution done with
a full AST walk). Nothing found here requires new Joern capability or a new CPG
node kind — every gap is either "we haven't exported it yet" or "we haven't
written the small classification table yet," not "Joern can't tell us this." The
one real blocker for a *general* (not fixture-specific) implementation is the
security-sensitive-sink profile (Q5), which is a policy/profile problem, not a
representational one, and should be scoped as its own follow-up (mirroring
`SINK-R01`/`SOURCE-R02`'s existing C++ pattern) rather than folded into R02.

## 5. Narrowest sound invariant we could promote

> **A guard on `instanceof`/equality/relational comparison protects the exact
> value it structurally checks (via REF), and only that value. If the checked
> value's producing CALL is a member of a closed set of builtins/operators with
> spec-fixed, argument-shape-sensitive coercion semantics that are known to
> destroy the prior value's failure discriminator, the guard must not be
> credited as protecting the original callee result — regardless of variable
> names, function names, or apparent intent.**

This is deliberately narrower than the general Fable principle restated in the
prompt: it only promotes the ERASES side (spec-fixed builtins), not the PRESERVES
side (structural passthrough proof) or the UNKNOWN side (abstention), because
those two still need their own small amount of new code (a passthrough checker,
an explicit default-to-UNKNOWN rule) before they can be called "implemented"
rather than "characterized." The ERASES side, by contrast, only needs the
condition-export gap closed and the closed builtin table written — both are
narrow, auditable, and don't require guessing about program intent anywhere.

## Reproduction

```bash
export JSSRC2CPG=/path/to/jssrc2cpg.sh JOERN=/path/to/joern
cd tests/gates/js-state-r01
mkdir -p run/src run/joern/raw run/joern/characterize
cp fixture/state_erasure.ts run/src/
"$JSSRC2CPG" run/src --output run/cpg.bin.zip
"$JOERN" --script ../../../frontends/javascript-typescript/joern-ts/export_ts_facts.sc \
  --param cpgFile=run/cpg.bin.zip --param outDir=run/joern/raw
"$JOERN" --script characterize.sc \
  --param cpgFile=run/cpg.bin.zip --param outDir=run/joern/characterize
"$JOERN" --script ref_based_guard_subject.sc \
  --param cpgFile=run/cpg.bin.zip --param outDir=run/joern/characterize
```

`characterize.sc` and `ref_based_guard_subject.sc` are characterization-only
observation scripts, not part of the promoted pipeline — they exist to answer
JS-STATE-R01's questions and are not wired into `run_all.py`.
