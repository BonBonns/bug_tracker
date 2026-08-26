# NoSQL injection: Stage 1 sink semantics, frozen. 10/10 fixture-verified, two real bugs found and
# fixed before freezing.

New property, `ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE`: does attacker-controlled input reach
a MongoDB query selector field without being constrained to a primitive (non-object) type, enabling
operator injection (`$ne`, `$regex`, `$gt`, `$where`)? Grounded in RocketChat's own repeated,
multi-year disclosed history of exactly this vulnerability class -- CVE-2021-22911
(`getPasswordPolicy`'s token field), HackerOne #3564655/CVE-2026-29198 (OAuth `access_token`
field), and GHSA-hgq6-9jg2-wf3f/CVE-2026-30833 (ddp-streamer username field) -- not a hypothetical
shape.

## A property-specific inversion worth stating up front, before Stage 2 is built
`typeof x === 'string'` was correctly EXCLUDED as a guard for command injection (doesn't restrict
shell-metacharacter content). For THIS property, that exact same construct is the actual defense --
MongoDB operator injection structurally requires an object (`{$ne: null}`), so ruling out
non-string types closes the vector entirely. Same syntax, opposite significance, because the
underlying property is different (type/structure control, not content control). Noted now so Stage
2's design starts from this correctly, rather than importing command injection's rule by habit.

## Sink families and per-field operand tracking
`findOne`, `find`, `updateOne`, `updateMany`, `deleteOne`, `deleteMany`, `countDocuments`,
`findOneAndUpdate`, `findOneAndDelete`, `findOneAndReplace`, `replaceOne` -- the selector is always
the first real argument, confirmed against real driver/Mongoose signatures. Each FIELD within the
selector object is tracked as its OWN operand pair (field identifier, value expression) -- matching
the per-operand discipline used for SSRF's options-object fields and command injection's args-array
elements, not treating the whole selector as one opaque blob.

## Two distinguishable field-identity shapes, matching a pattern from command injection
    LITERAL_FIELD  -- a fixed, known field name (`{ username }`, `{ 'services...token': token }`)
    COMPUTED_FIELD -- a dynamic, attacker-influenceable key (`{ [fieldName]: fieldValue }`) --
                      structurally distinct and arguably worse (attacker controls WHICH field gets
                      overwritten, not just its value), kept separate rather than conflated,
                      mirroring the same distinction already established for command injection's
                      `allowlist[x]` indexAccess case.

## Result: 10/10 correct, two real bugs found and fixed before freezing
    findOneSingleField           -> field=username                          value=username
    findOneExplicitKeyValue      -> field=services.password.reset.token     value=token
    findMultiple                 -> field=userId                            value=userId
    updateOneSelector            -> field=_id                               value=recordId
    deleteOneSelector            -> field=sessionId                         value=sessionId
    countDocumentsSelector       -> field=status                            value=status
    findOneMultipleFields        -> field=email                             value=email
                                     field=active                            value=true (fixed literal,
                                       correctly enumerated regardless of attacker control -- that
                                       determination is Stage 3's job, not Stage 1's)
                                     field=statusFlag                        value=active (same source
                                       variable feeding a DIFFERENT field -- correctly tracked as its
                                       own distinct operand)
    attackerControlsFieldName    -> field=fieldName (COMPUTED)               value=fieldValue

## Two real bugs found and fixed
1. **Dotted MongoDB field paths were truncated**: `fld.code.split("\\.").lastOption` treated a
   literal object key containing dots (`'services.password.reset.token'`, MongoDB's own dot
   notation for nested fields -- the EXACT real field name from CVE-2021-22911) as if it were a
   chained field-access expression, extracting only the last segment ("token") and silently
   discarding the rest. The tracked VALUE operand was still correct (this didn't affect dataflow
   tracing), but the reported field identity was wrong -- a real defect for anything downstream
   that needs to tell a reviewer WHICH field is affected. Fixed by extracting everything after the
   first '.' following the receiver, preserving the full literal key.
2. **Wrong argument index for computed-key values**: assumed `indexAccess`'s key argument was at
   index 1 (matching this project's usual receiver-then-content convention), but confirmed by
   direct inspection that `indexAccess` puts the RECEIVER at index 1 and the KEY at index 2 -- a
   genuinely different indexing convention from the member-call/fieldAccess pattern used
   everywhere else in this project. Initially reported the receiver's own temp-variable name
   (`_tmp_9`) as the "field," not the actual key expression (`fieldName`). Fixed by checking the
   real structure directly before assuming the established convention transferred.

## What was explicitly NOT done (per every prior Stage 1 in this project)
No type-guard/property-effect classification (that's Stage 2, next -- and per the inversion noted
above, needs its own careful design, not a copy of any prior property's rule set). No wiring into
the adjudicator. No corpus scanning. Not characterized: aggregation-pipeline queries (`.aggregate()`,
a structurally different, more complex sink shape), raw driver `$where` clauses passed as strings
(a separate, string-based injection vector rather than the type-confusion vector this property
targets), and GraphQL/REST-layer input validation happening upstream of the query call (a real,
separate mitigating factor, analogous to how RocketChat's `Message_MaxAllowedSize` bounded the
ReDoS findings -- deferred to vulnerability adjudication, not Stage 1's job).

## Status
Sink-semantics matrix: frozen, 10/10 fixture-verified, two real bugs found and fixed before
freezing -- one a data-fidelity issue (truncated field names), one a wrong-index assumption caught
by checking real structure rather than trusting a prior convention to transfer automatically. Ready
for Stage 2: type-guard/property-effect classification, designed from the ground up around this
property's actual defense mechanism (type constraint, not content constraint) rather than adapted
from a different property's rules.
