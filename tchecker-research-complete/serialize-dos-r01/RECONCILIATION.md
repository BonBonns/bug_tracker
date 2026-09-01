# Serialize DoS: reconciling the two independent implementations

Two implementations in this repository both carry a "serialize-dos"/CWE-674 label. Per
instruction, neither is assumed canonical until both are executed against their own
existing controls and compared exactly. Both were run this session, independently, with
this session's own Joern 4.0.608 toolchain (Maven-assembled classpath +
`io.joern.joerncli.console.ReplBridge`, astgen 3.47.0 built from source) — not merely
read from prior documentation.

## 0. Baseline runs, this session, against real compiled facts

- `gates/gate_serialize_dos.py` (direct fact-based): re-run against its existing fixture
  → `SERIALIZE_DOS=9/9`, `PROMOTION_GATE=PASS` (unchanged from prior).
- `tchecker-property-adjudicator` (taint-engine, via its `recovered/serialize-dos-snapshot-2026-08-23/`
  demo fixtures): independently rebuilt CPGs from `demo_direct.js` and
  `demo_lookup_falsepos.js` and ran the full producer chain
  (`setup_candidate.sc` → `export_property_propagation.sc` → `export_trace_identity.sc` →
  `adjudicate_js.py`) myself, from source, with no reuse of any pre-existing fact files:
  - `demo_direct.js` → `property_outcome=ESTABLISHED`,
    `disposition=RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS` — matches
    `VERIFICATION.md`/`RECOVERED.md` exactly.
  - `demo_lookup_falsepos.js` → `property_outcome=NO_FLOW`,
    `disposition=REJECTED_NO_STRUCTURAL_FLOW` — matches `RECOVERED.md`'s 2026-08-24
    re-verification exactly (note: the outer package `README.md`'s own command listing
    for this fixture is stale, still showing the older `BROKEN`/`REJECTED_FALSE_POSITIVE`
    labels that `RECOVERED.md` superseded — a doc-staleness note, not a functional issue).

Both implementations run cleanly against their own existing controls. Neither is
disqualified by that test. The question is whether they model the same property.

## 1. Verdict: NOT the same property — preserved as two subproperties

They share a vulnerability-class label (serialize-dos, CWE-674, `JSON.stringify` as the
downstream primitive) but model two structurally different resource-exhaustion
mechanisms, with disjoint guard vocabularies, disjoint fact schemas, and different
depth of analysis. Forcing them into one flat verdict would silently drop real
information in both directions (a flow the crash-model calls `SAFE_TRY_CATCH` can still
be `RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS` under the size-model, and vice versa — see
§3). Per instruction, they are preserved as two subproperties of one canonical
property-local revision, never combined into a single verdict field.

- **Subproperty A — `CRASH_DOS`** (the direct/`gates/` implementation's model): a
  synchronous `RangeError` from serializing deeply-nested attacker JSON, uncaught, kills
  the whole Node process on a single unauthenticated request. The GHSA-r5pq-6chh-j3xp
  (Unleash) shape.
- **Subproperty B — `SIZE_STRUCTURE_DOS`** (the taint-engine's model,
  `ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE`): attacker-controlled data reaches a
  serialization sink with its size/structure not demonstrably bounded by any on-path
  transform — a broader resource-cost question (CPU/memory/event-loop-blocking),
  independent of whether any particular call happens to throw or crash.

## 2. Exact comparison

| axis | `gates/serialize_dos_verdict.py` (direct) | `tchecker-property-adjudicator` (taint-engine) |
|---|---|---|
| **Serialization operations covered** | `JSON.stringify` AND `util.inspect` (both matched by the same producer, `export_serialize_facts.sc`, one pass) | `JSON.stringify`/`EJSON.stringify` per `property_configs/serialize_dos.json`'s `direct_sink_kinds`, but the actual producer (`setup_candidate.sc`) hardcodes `cpg.call.name("stringify").headOption` — one sink, first match only, no `util.inspect` handling anywhere in the pipeline despite the "generic" framing at the adjudicator layer |
| **Input/source boundaries** | Regex-based, multi-framework, in one automated pass: Express/Koa `req.body`, `ctx.request.body`, Hapi `request.payload`, Fastify `request.body/query/params`, Express `req.query`/`req.params`, plus a `lodash.get(body)` accessor form | A single explicit `srcPattern` string supplied per invocation (e.g. `"req.body"`) via `--param srcPattern=`; not simultaneously multi-framework — one run covers one literal source-code pattern, matched via `codeExact` or a wrapped-substring regex |
| **Guard/bound requirements modeled** | Process-crash safety nets only: lexical `try/catch` around the sink, a depth/size-guard call or comparison in the same method, a package-level `process.on('uncaughtException', ...)` handler. A `bounded_literal` heuristic (freshly-built object/array literal of scalars) exists but is narrow (structural literal shape, not general transform tracking) | Whether an on-path **transform** (a user-defined, non-builtin call between source and sink) bounds the serialized size/structure — resolved deterministically only when the flow is **direct** (no transform: automatic `ESTABLISHED`); when a transform exists, the question ("does this call bound serialized size?") is deferred to semantic/LLM review (`CANDIDATE_OPEN`) unless a hint is supplied. **No modeling anywhere of `try/catch` or `uncaughtException`/`unhandledRejection`** — confirmed by exhaustive grep of `adjudicate_js.py` and all three producers: zero matches for `trycatch`, `uncaughtException`, or `process.on` outside of an unrelated `BUILTIN` name-exclusion set that happens to list `"catch"` as a builtin *method name* to skip when scanning for transforms, not as a guard concept |
| **Interprocedural behavior** | **Intraprocedural only.** Attacker-taint tracking (`export_serialize_facts.sc`'s `tainted` set) is reset per method; a value laundered through a helper function's return is explicitly disclosed as under-approximated in the module's own docstring | **Genuinely interprocedural.** `export_trace_identity.sc` resolves a transform call to "EXACTLY ONE callee body... via actual `MethodParameterIn` entry on the dataflow path," and the property-propagation layer follows transform chains across calls. Independently confirmed generalizing to unseen out-of-corpus TypeScript in `TS_GENERALIZATION.md` (`novuhq/novu`, a `this.`-member-method transform correctly and uniquely trace-identified) |
| **Candidate/negative/abstention vocabulary** | Flat, 6-way, 100% deterministic enum, every sink gets exactly one verdict, no abstention state: `CANDIDATE_UNGUARDED_SERIALIZE_DOS`, `SUSPICIOUS_UNGUARDED_SERIALIZE`, `SAFE_TRY_CATCH`, `SAFE_DEPTH_GUARDED`, `SAFE_NOT_ATTACKER_CONTROLLED`, `SAFE_BOUNDED_LITERAL` | Richer state machine with a genuine abstention state: `NO_FLOW`/`BROKEN` → `REJECTED_NO_STRUCTURAL_FLOW` / `REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED` (negative); `OPEN` → `CANDIDATE_OPEN` (**abstention** — awaits semantic review, never auto-resolved) or, with a supplied hint, `RESOLVED_CANDIDATE_BY_ACCEPTED_HINT` / `RESOLVED_SAFE_BY_ACCEPTED_HINT` (hint-dependent, and explicitly documented as never rewriting the underlying deterministic fact — `deterministic_status` stays `UNKNOWN` even after a hint is folded); `ESTABLISHED` → `RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS` (candidate, fully deterministic) |
| **Required fact schemas** | 3 tables, 1 producer (`export_serialize_facts.sc`): `serialize_sinks.tsv` (8 col), `uncaught_handlers.tsv` (2 col), `depth_guards.tsv` (2 col) | 7 tables, 3 producers (`setup_candidate.sc`, `export_property_propagation.sc`, `export_trace_identity.sc`): `source_facts.tsv`, `propagation_relations.tsv`, `transform_identity.tsv`, `trace_identity.tsv`, `definition_resolution.tsv`, `property_outcome.tsv`, `property_propagation.tsv`. **Disjoint from the direct implementation's schema — no shared table, no shared column** |
| **Existing fixtures / real evidence** | 8 hand-scenario fixtures, real compiled CPG present (`fixtures/ser-out/cpg.bin`, 77KB, non-trivial — genuinely Joern-compiled, not hand-authored TSV), gate 9/9. **Zero real-npm-package runs anywhere in this repository** (confirmed by repo-wide grep of the analyzer's own schema string) | 4 demo fixtures (re-verified fresh-sandbox 2026-08-24, and independently re-verified again this session for 2 of the 4), PLUS one real-corpus run: `mozilla/fxa`'s `customs.js`/`emails.js` (`fixtures/customs_dos_serialize/`, real compiled facts) — result: 4 sink/source pairs, all `OPEN` (a genuine real-package candidate requiring semantic review, not an autoresolved positive), PLUS a held-out TypeScript generalization test on `novuhq/novu` (unseen at development time) documented in `TS_GENERALIZATION.md`, including one honestly-disclosed real limitation (a `reachableByFlows` path-enumeration edge case that can short-circuit to a spurious `BROKEN` before an intended `OPEN`) |
| **Known soundness limitations (self-disclosed)** | (a) intraprocedural-only — helper-return laundering under-approximated; (b) `try/catch` guard detection is lexical, so a serializer called from a callback that escapes an enclosing `try` (async) is conservatively flagged as guarded — a disclosed false-negative direction; (c) `uncaughtException` net is a package-level fact, may miss a real monorepo's actual entrypoint | (a) `setup_candidate.sc` hardcodes the sink to call-name `"stringify"`, first match only — no multi-sink, no `util.inspect`; (b) one explicit `srcPattern` per run, not simultaneous multi-framework; (c) `OPEN` cases are fundamentally unresolved without an accepted semantic hint — never autonomously resolvable; (d) `reachableByFlows` can enumerate a spurious tangential path and short-circuit past the intended `OPEN` branch (real, disclosed, observed on `novuhq/novu`) |

## 3. Why they are not the same property (concrete, not just structural)

Take a value serialized inside a `try/catch` block via a transform whose bounding effect
is genuinely unknown (e.g. a caller-supplied formatter): the direct implementation
reports `SAFE_TRY_CATCH` — the crash is prevented, so by its own (crash-only) model
there is nothing left to report. The taint-engine reports `CANDIDATE_OPEN` — the
resource cost of serializing unbounded attacker data is not addressed by catching the
resulting exception; a caught `RangeError` still means the CPU/memory was already spent
constructing the string up to the point of failure, and a bounded-but-not-crashing
payload might not throw at all while still costing real resources repeatedly. Neither
verdict is wrong; they are answering different questions. This is the concrete case the
comparison predicts and the two implementations' own vocabularies confirm.

## 4. Decision

Preserve both subproperties. The canonical property-local revision built in this
directory (`serialize_dos_r01.py`) computes **two independent classification axes per
finding** — `crash_dos_classification` (reusing the direct implementation's proven
guard model) and `size_structure_dos_classification` (a new, deterministic-only,
conservative structural approximation of the taint-engine's question, explicitly
**not** a reimplementation of its interprocedural transform-chain engine — see
`serialize_dos_r01.py`'s own docstring for the exact, disclosed scope reduction) — never
merged into one flat verdict, and reports both.
