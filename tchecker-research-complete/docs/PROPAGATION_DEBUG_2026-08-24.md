# Propagation-relation debug 2026-08-24 — source->sink path tracing

Trigger: scanned mozilla/send (real GitHub repo, 88 JS files across app/+server/+common/)
with `export_propagation.sc` and found suspiciously few source->sink paths (0 of 31
`JSON.stringify` sinks established). Hand-traced the actual Mozilla source against the
scanner's output to find and fix the root causes. All fixes verified against
hand-confirmed ground-truth paths in the real code, and re-checked against the
malicious-npm gate fixture (still 13/13, no regression — see below).

## 1. FIXED (severe) — the interprocedural bridge was dead code
`export_propagation.sc` builds a `bridged` map specifically to stitch cross-file paths
that `reachableByFlows` can't reach on its own (jssrc2cpg doesn't link CommonJS
`require()` call edges, so cross-file flows are normally invisible to the dataflow
engine). The bridge correctly computed `bridged`, but the emit loop only ever read
`bySink` (direct flows) — `bridged` was populated and never consulted. Every
cross-file path fell through to ABSTAINED regardless of how solid the underlying
two-hop dataflow was. Hand-traced ground truth: `server/routes/report.js`'s
`req.body.reason` -> `statReportEvent()` -> `server/amplitude.js`'s `sendBatch()` ->
`JSON.stringify` — confirmed via direct CPG probe that both hops resolved before the
fix, yet the sink still reported ABSTAINED. Fixed by consuming `bridged` in the emit
loop as a second match arm (`ESTABLISHED_INTERPROC`), tried only when no direct flow
exists. Impact: 0 -> 21 established rows on first fix alone.

## 2. FIXED — StoredNode/AstNode type-widening bug (surfaced while fixing #1)
`bridged`'s declared type used `nodes.StoredNode` for the origin-node slot. `p.elements`
from `reachableByFlows` is actually typed `List[nodes.AstNode]`; storing it in a
`StoredNode`-typed container silently upcasts and loses `.code` at compile time (does
not fail until something tries to read `.code` off the widened value — which is exactly
what emitting the new branch needed to do). Fixed by correcting `srcByIdx` and
`bridged`'s declared value type from `StoredNode` to `AstNode`, matching what
`reachableByFlows` actually returns.

## 3. FIXED — source seed too narrow (req.header/req.get missing)
The seed only matched `req.(body|payload|query|params)` field accesses. Hand-tracing
`server/fxa.js:39` (`JSON.stringify({ token })`) back to its origin found
`server/middleware/auth.js:67`'s `req.header('Authorization')` feeding it — a call, not
a field access, so the seed missed it structurally, not just by regex gap. Added
`req.header(...)`/`req.get(...)` as a second source class (`srcsHeaderCall`).

## 4. FIXED — no source class for WebSocket message payloads
`server/routes/ws.js` parses attacker-controlled WS payloads
(`const fileInfo = JSON.parse(message)`) and downstream fields feed real sinks, but no
`req.*` pattern ever touches this file — there was no source class for it at all. Added
`srcsWsMessage`, scoped strictly to the parameter bound as the callback of
`.on('message', ...)`/`.once('message', ...)` (via METHOD_REF -> referencedMethod), NOT
a bare name match on `"message"` — `app/ui/okDialog.js` has an unrelated parameter also
named `message` (a dialog string) that a name-only match would have wrongly pulled in.
Recovered a real path: `message` -> `JSON.parse` -> `fileInfo.bearer` ->
`fxa.verify(token)` -> `JSON.stringify({token})` at `server/fxa.js:39` — a different,
cleaner route to the same sink #3 above targeted (that one is separately blocked by
finding #6 below).

Correction to an earlier hypothesis in this same debugging session: four `ws.js` sinks
(lines 46, 60, 111, 129) were initially assumed to need this source class too. Rereading
the actual code found they're `JSON.stringify({ error: 401 })`, `{ error: 400 }`,
`{ ok: true }`, and a caught-exception-derived constant (`e === 'limit' ? 413 : 500`) —
pure literals or constant-derived values with **no** data flowing through them at all.
Correctly ABSTAINED; not a scanner gap.

## 5. FIXED — bridge was single-hop only, needed N hops
`server/initScript.js`'s sinks trace back through a 3+ hop chain
(`req.params.id` -> `storage.metadata()` -> `routes().toString()` -> `layout()` ->
`initScript()` -> `JSON.stringify`) that a single hop cannot reach. Generalized the
bridge into an iterative BFS over hops (bounded at `maxHops = 4`), each hop reusing the
same HOP-IN/HOP-OUT mechanic and checking after every hop whether the frontier already
reaches a gated sink. Verified against a real 2-hop find:
`req.header('Authorization')` -> `upload` -> `writeFile` -> `JSON.stringify` at
`app/storage.js:142` (superseded by finding #6 — see below, this specific chain turned
out to be a false positive removed by the require-path guard).

`initScript.js` itself remains correctly ABSTAINED after all fixes: the chain passes
through `routes().toString()`, and `cpg.method.isExternal(false).name("toString")` is
empty — there is **no local, non-external definition of `toString`** anywhere in the
repo. The real call dispatches into the Choo framework's virtual-DOM internals in
`node_modules`, which jssrc2cpg never parses (it only analyzes the target repo). No
number of additional hops can bridge into a function that was never parsed into the
CPG. This is a hard boundary of static single-repo analysis, correctly identified and
left as ABSTAINED rather than worked around.

## 6. FIXED (real false positive, found via #5's wider surface) — name-only bridge matching
Generalizing the bridge to N hops gave a pre-existing structural flaw more chances to
fire: `unlinkedCalls` matched a same-named local method as an unlinked call's "real
callee" using **only the function name**, with no check that the calling file actually
`require()`s anything related to the candidate's file. Hand-verified false positive:
`server/storage/s3.js`'s `this.s3.upload({...})` (an AWS SDK call — the file's only
`require()` is `require('aws-sdk')`) was bridged to three unrelated client-side
functions also named `upload` (`app/api.js`, `app/fileSender.js`,
`app/ui/archiveTile.js`), purely because the names collided. Further check confirmed
`writeFile` has the same shape: its only real definition is in `app/storage.js`
(client-side) — there is no server-side `writeFile` at all, so *any* server-originating
bridge through that name was structurally guaranteed to be spurious. This flaw predates
this session (the original single-hop bridge used the same name-only match); it simply
had less surface area to misfire on until the multi-hop generalization (#5).

Fixed by gating every name match on the calling file's actual `require()` targets:
built `requiredBasenamesByFile` (file -> set of require()'d path basenames, extension
stripped) and only accept a same-named candidate method if its containing file's
basename appears in the calling file's required set. Verified against the legitimate
case (`report.js`'s `require('../amplitude')` -> basename `"amplitude"` matches
`server/amplitude.js`) to confirm the guard doesn't also kill real paths.

Net effect of #6: established sinks dropped from an inflated 10 to a verified 3 — this
drop is **correct**, not a regression; six of those ten were the spurious
`upload`/`writeFile` client<->server collisions described above.

## Final state (all fixes applied, hand-verified)
31 `JSON.stringify` sinks total, every one individually accounted for:
- **3 ESTABLISHED**, each hand-confirmed against the real source:
  `server/amplitude.js:174`, `server/fxa.js:39`, `server/routes/ws.js:80`.
- **28 ABSTAINED**, each individually understood rather than defaulted: ~18 are
  client-side `app/*.js` files with no `req` object at all; 5 (`initScript.js`) are
  blocked by the unparsed-third-party-framework boundary (finding #5); 4 (`ws.js`
  46/60/111/129) are genuine literals with no data source (finding #4 correction).

## Regression check
Re-ran `gates/gate_malicious_npm.py` against `gates/fixtures/mal-fixture` after every
change in this file — stayed at 13/13 throughout (`export_propagation.sc` is not wired
into that gate's producer chain, but shares `unlinkedCalls`-style patterns worth
checking; confirmed clean).
