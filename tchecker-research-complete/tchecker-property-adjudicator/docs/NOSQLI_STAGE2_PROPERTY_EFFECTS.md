# NoSQL injection Stage 2: property effects, frozen. 9/9 fixture-verified, one real bug found and
# fixed before freezing.

Built from the ground up around this property's actual mechanism (type constraint), not adapted
from any prior property's rule set. Verifies the one genuine design decision stated before any
fixture existed: a closed-type-system asymmetry-breaker specific to this property.

## The central design decision, stated and verified, not just asserted
JavaScript's `typeof` has a CLOSED, finite output set (`"undefined","object","boolean","number",
"bigint","string","symbol","function"`). Unlike command injection's open-ended shell-metacharacter
space -- where only positive allowlisting could ever be trusted, since a blacklist can never
enumerate every dangerous character with confidence -- a type check against this closed set CAN be
structurally complete in both directions. Two forms are recognized as genuine, complete guards:
    typeof x === 'string'   (positive: explicitly requires the one safe type)
    typeof x !== 'object'   (negative: excludes the one dangerous type -- complete BECAUSE the
                              output set is closed, there is no "unknown ninth type" that could
                              sneak an object-shaped operator injection through)
Deliberately narrow: other typeof comparisons (checking for `'number'`/`'boolean'` positively, or
excluding `'function'`/`'symbol'` negatively) are NOT credited as complete guards against
object-based operator injection specifically -- verified this distinction is enforced, not just
described, by testing exactly these two forms and no others.

## Two NEW guard-dominance mechanisms, distinct from every prior property
1. **If-block dominance** (reused, verified again in this new context): `typeof` checks gating the
   sink inside an `if` block.
2. **Statement-order dominance, genuinely new to this property**: `Meteor.check(value, String)` is
   a synchronous, throw-on-mismatch primitive -- its mere presence as an EARLIER STATEMENT in the
   same straight-line method body is sufficient, with no `if` block required at all. This needed
   its own mechanism, not a reuse of if-block dominance, since `check()` doesn't gate anything
   syntactically -- it aborts execution via exception if the type doesn't match. Documented as the
   same "v1 syntactic approximation" limitation as every dominance check in this project (earlier
   in AST/statement order, not full CFG dominance).

## Coercion as a distinct, non-guard mechanism
`String(x)` and template-literal interpolation (`` `${x}` ``) both force genuine string conversion
regardless of x's original type -- `String({$ne: null})` produces the literal string
`"[object Object]"`, not an interpretable operator. Verified both forms reuse the same detection
approach already established this session (direct `String()` call; `<operator>.formatString`
membership for template literals), confirming the underlying CPG representation transfers cleanly
across properties.

## The asymmetric discipline, carried forward and grounded in this exact codebase's real history
Field/character blocklists NEVER count as BREAKS, regardless of apparent thoroughness --
`incompleteFieldBlocklist` checks whether specific FIELD NAMES are being queried but never
inspects the VALUE's type, so `$ne`/`$regex`/`$where` all pass through untouched. This is not a
hypothetical case: it is the EXACT shape of RocketChat's own disclosed 2021 bypass (Sonar's
writeup: a blocklist checking known query fields, defeated via the `$where` top-level operator it
never considered). Also verified a genuinely INCOMPLETE type check stays PRESERVES:
`Array.isArray(x)` alone does not exclude plain objects -- `{$ne: null}` is an object, not an
array, so this check provides no real protection despite superficially looking like a type guard.

## Result: 9/9 correct, one real bug found and fixed before freezing
    noGuard                              -> PRESERVES
    typeofStringPositiveDominates        -> BREAKS   (typeof x === 'string', dominates)
    typeofStringPositiveDoesNotDominate  -> PRESERVES (guard present, doesn't dominate)
    typeofObjectNegativeDominates        -> BREAKS   (typeof x !== 'object', dominates)
    stringCoercion                       -> BREAKS   (String(x))
    templateLiteralCoercion              -> BREAKS   (`${x}`)
    meteorCheckString                    -> BREAKS   (Meteor.check(x, String) precedes sink)
    incompleteFieldBlocklist             -> PRESERVES (checks fields, never checks value type)
    incompleteArrayOnlyCheck             -> PRESERVES (excludes arrays, not plain objects)

## One real bug found and fixed
Classic off-by-one on a member call: `Meteor.check(userInput, String)` has its receiver
(`Meteor`) at argument index 0, the tracked value at index 1, and the type pattern at index 2 --
the same convention used throughout this project for member calls, but the check-dominance logic
initially used `.headOption`/`.lift(1)` (as if index 0 were the tracked value directly), silently
checking the wrong two argument positions. Caught by debugging the actual argument structure
directly rather than assuming the pattern from a plain-function-call context would transfer
unchanged to a member call.

## What was explicitly NOT done
No wiring into the adjudicator, no property config written, no corpus scanning. Not characterized:
Mongoose schema-level type coercion (a real, separate mitigating factor operating outside the
query-call code itself -- analogous to how `Message_MaxAllowedSize` bounded the ReDoS findings --
correctly deferred to vulnerability adjudication, not Stage 2's job), aggregation-pipeline
`$match` stages (a structurally different sink shape from direct selector objects), and
`$where`/raw-JavaScript-string query clauses (a separate, string-based injection vector distinct
from the type-confusion vector this property targets).

## Status
Property-effects matrix: frozen, 9/9 fixture-verified, one real bug found and fixed before
freezing. Ready for Stage 3: integration into the parameterized adjudicator and testing against a
real corpus -- RocketChat is the natural first target, given this property was built directly from
its own repeated, disclosed vulnerability history.
