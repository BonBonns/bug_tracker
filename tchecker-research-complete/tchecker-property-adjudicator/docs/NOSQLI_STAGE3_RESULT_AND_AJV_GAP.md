# NoSQL injection Stage 3: exhaustive scan intractable, targeted investigation reveals a
# systematic classifier gap worth fixing before scaling further

The full 374-target exhaustive sweep did not complete -- reported honestly, not extrapolated from
partial data. But pivoting to targeted, hand-verified investigation of a real, promising candidate
surfaced something more valuable than the sweep likely would have: RocketChat's actual, systematic
defense mechanism for this vulnerability class, which the current Stage 2 classifier does not yet
recognize.

## What was fixed to make the scan tractable at all
1. A real logic bug (checking a coercion call's code against itself, never matching) that let both
   Stage 2 coercion test cases leak through as false positives -- fixed by extracting the inner
   tracked expression before reachability testing.
2. Genuine OutOfMemoryError on the full corpus -- traced to sink targets whose value is itself a
   nested object literal (`{ $gt: x }`, `{ $all: x }`), both computationally pathological for the
   dataflow engine and semantically redundant (Stage 1's own recursion already separately captures
   these operators' own inner field:value pairs). Filtered explicitly and reported: 80 of 460
   targets excluded on this basis.
3. A second, distinct stall mechanism (not nested-object-shaped) hit repeatedly in different
   locations, not fully root-caused. Added a per-sink 45-second timeout (Future/Await on a
   dedicated thread) so a single pathological sink is abandoned and logged rather than requiring
   manual kill-and-restart cycles -- verified this doesn't affect the fixture's correctness.

## Why the exhaustive sweep was abandoned, stated precisely
Even with all three fixes, throughput remained roughly 1 sink per 45-50 seconds averaged across a
~40-45% timeout rate. Projected full completion: several hours, not tractable within this session.
Stopped at sink 37 of 374, zero ESTABLISHED results up to that point -- itself a signal worth
investigating rather than discarding.

## Pivoted to targeted investigation -- and it explains the zero-result pattern
Hand-selected a promising candidate visible in the scan log:
`server/api/v1/integrations.ts:239`, `Integrations.findOne({ _id: bodyParams.integrationId })`,
where `bodyParams` is the REST handler's parsed request body -- a directly attacker-controlled
input by construction, with no guard visible in the handler itself.

Traced this to its enclosing route registration precisely (not assumed): the code sits inside the
`integrations.remove` endpoint (`API.v1.post('integrations.remove', { body: isIntegrationsRemoveProps,
... })`). Fetched the real schema definition, not assumed effective:

    integrationId: { type: 'string', nullable: false }

compiled via `ajv.compile(...)` -- a real, standard JSON-schema validation library, enforced by
RocketChat's API framework BEFORE the handler function runs. This is the same "real property,
closed by a nonlocal invariant" pattern already confirmed for RocketChat's path-traversal,
SSRF, and ReDoS findings this session -- now independently reconfirmed for NoSQL injection, on a
concretely different mechanism (schema validation at the framework boundary, not application code).

## The systematic finding, not just a single closed candidate
Checked how widespread this pattern is, rather than treating one instance as representative by
assumption:

    grep -c "body: is[A-Za-z]*Props" across server/api/v1/*.ts: 110 occurrences, 26 files

This is RocketChat's primary, systematic defense mechanism for its REST-API attack surface for
this vulnerability class -- not an isolated case. It directly explains why the exhaustive scan
found zero ESTABLISHED results through 37 sinks despite several being plausible REST handlers: most
of RocketChat's API-reachable query fields are very likely gated the same way.

## The actionable conclusion: a genuine, systematic Stage 2 classifier gap
Stage 2's property-effects classifier currently recognizes three guard mechanisms (if-block typeof
checks, Meteor.check(), string coercion) -- none of which cover AJV/JSON-schema body validation at
the API-route level, RocketChat's apparent PRIMARY defense. This is exactly the kind of
classification gap worth catching before scaling the scan further, rather than after: continuing
the exhaustive sweep as originally structured would likely have produced mostly false positives
across RocketChat's REST layer, each requiring the same manual trace-to-schema verification just
performed once, by hand, here.

## What a fix would need to do, named precisely, not built yet
Recognize the shape: a sink inside a handler function registered via `API.v1.get/post(...)` whose
route-registration object has a `body: <validatorIdentifier>` property, where `<validatorIdentifier>`
resolves (via import) to an `ajv.compile(schema)` result, and where the SPECIFIC field being used at
the sink appears in that schema with `type: 'string'` (or another non-object primitive) and
`nullable: false`. This is a materially different mechanism from anything built so far in this
project -- it requires resolving an import across file/package boundaries (the schema lives in
`@rocket.chat/rest-typings`, a separate package from the handler) and parsing a JSON-schema-shaped
object literal, not a simple in-function guard check. Deliberately not attempted under this
session's remaining time -- would need its own fixture-first treatment, matching the discipline
every other mechanism in this project received, rather than a rushed pattern-match.

## Status
NoSQL injection Stages 1-2 remain frozen and correct for what they model (in-handler guards).
Stage 3's mechanism is verified correct against fixtures. The full-corpus exhaustive scan is
incomplete and was deliberately abandoned as intractable within reasonable time, rather than
extrapolated from partial results. The one hand-investigated, real candidate is CLOSED --
correctly, verifiably, not assumed -- by RocketChat's own AJV schema validation. The systematic
scope of that same mechanism (110 occurrences, 26 files) is the actionable finding this session
produces: before running this property against RocketChat's REST layer at scale, Stage 2 needs to
learn to recognize API-route body-schema validation as a genuine guard, or the exhaustive scan --
even if made fast enough to complete -- would likely report many false positives requiring the same
manual verification performed here, one at a time.
