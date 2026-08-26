# NoSQL injection scanner: two real fixes from the manual-investigation findings, both verified

## Fix 1: headers excluded from this property's source pattern
HTTP headers, retrieved via .headers.get(name), are structurally always strings or null by
protocol -- they cannot carry the object-shaped payload ({"$ne": null}) this property targets,
unlike req.body (parsed JSON, any shape) or req.query (some parsers support bracket notation
producing nested objects -- the actual mechanism behind RocketChat's real disclosed
access_token[$ne]=null CVE). Confirmed necessary by a real false lead this session (x-user-id/
x-auth-token in ApiClass.ts, requiring manual tracing to rule out). SOURCE_PATTERN for this
producer specifically no longer includes headers; the general SOURCE_PATTERN used by other
properties (SSRF, path traversal, command injection) is untouched, since headers ARE relevant
sources for those properties.

## Fix 2: AJV route-schema-gate detection, fixture-first, with a real bug caught before freezing
RocketChat's REST API layer (confirmed 110+ occurrences across 26 files in api/v1 alone) gates
many query fields behind AJV JSON-schema validation via `body:`/`query:` options on
API.v1.get/post(...) route registrations. The producer previously had no way to recognize this,
so gated-but-unresolved sinks fell through to PRESERVES -- directly responsible for the four false
leads chased by hand this session (each requiring cross-package schema resolution to rule out).

Built the detection fixture-first: four cases (body-gated, query-gated, API route with NO gate,
and a plain Meteor method entirely outside this mechanism) based directly on RocketChat's real
structural pattern. First implementation used string-based methodFullName matching to connect a
sink's enclosing `action()` method back to its route registration -- caught a real jssrc2cpg
ambiguity before trusting it: three unrelated action() handlers across different route
registrations all shared the identical fullName string ("file.js::program:action"), a genuine
naming collision, not a hypothetical edge case. Fixed by using MethodRef's `.referencedMethod`
node-ID resolution instead of the ambiguous name string. Re-verified: 4/4 correct, including
correctly distinguishing "API route but no schema gate at all" from "API route with a gate."

## The conservative design decision, stated precisely
A detected-but-unresolved gate is now reported as an explicit exclusion category (UNKNOWN),
never silently folded into PRESERVES. This producer does not attempt to resolve the schema itself
(the schema is typically defined in a separate package, @rocket.chat/rest-typings, not always
present in a given corpus) -- it only detects that a gate EXISTS structurally, which is enough to
stop mis-reporting these as exploitable without manual verification, matching exactly what four
hours of hand-tracing this session would have been spared by having.

## A real, fixed shadowing bug found while integrating
Wiring both fixes into the shared classification pipeline initially reintroduced a stale variable
reference (`preservesTargetsRaw`) after a rename, which would have caused a compile failure --
caught before running, not after.

## Full regression sweep, confirming nothing else was disturbed
customs.js evidence byte-identical to the established baseline. Both permanent serialize-DoS tests
pass. ReDoS Stage 2 fixture still 8/8 -- confirmed this producer's changes are correctly isolated
to its own file, not touching shared logic used by other properties.

## Status
Both fixes verified against dedicated, real-pattern fixtures before being trusted, and against the
existing NoSQL injection Stage 2 fixture (still 4/9 PRESERVES, 7 rows -- unchanged, as expected,
since that fixture contains no API-gated or header-sourced cases). Ready to rerun against the full
RocketChat corpus with meaningfully fewer false leads than the version that produced four manual
investigations this session.
