# Security-Property Propagation for Static Serialize-DoS Adjudication in JavaScript/TypeScript

A technical writeup of the TChecker adjudication pipeline: what it does, why it is built the way it
is, the negative results that shaped it, and how it held up on held-out code.

---

## 1. Problem and thesis

Static taint analysis over a Code Property Graph (here, Joern's `reachableByFlows`) answers a
reachability question: *can a source reach a sink through the data-dependence graph?* Security
adjudication needs a different, stronger question: *does the specific dangerous property the finding
depends on actually reach the sink?*

For serialize-DoS the finding is "attacker-controlled input is serialized without a size bound, so a
large request produces a large serialization." The property that must survive to the sink is
therefore **attacker control of the serialized size or structure** — not generic taint.

The central claim of this work, borne out by a real corpus false positive, is that these two
questions are not equivalent, and that inserting an explicit **security-property propagation** layer
between structural reachability and any semantic (LLM) review both removes real false positives and
makes the remaining semantic questions well-posed.

The pipeline that resulted:

    Joern reachableByFlows
      -> structural / data dependence          (frozen structural producers)
      -> TChecker security-property propagation (the layer this work adds)
      -> security-relevant path
      -> LLM semantic review ONLY IF the property remains UNRESOLVED
      -> disposition (follows the property layer)
      -> vulnerability-level adjudication       (out of scope for the static core)

---

## 2. The motivating negative result

The work began with a candidate in `mozilla/fxa` (`emails.js`, `normalizeEmail`) that looked like a
clean HTTP-input-to-serialization path. Rendering the complete source-to-sink code context revealed
the path was invalid as an *attacker-value* path:

- `request.payload.email` is normalized and then used as a **database lookup key**
  (`db.getSecondaryEmail(normalizedEmail)`); the returned record is DB-derived, not attacker-derived.
- The record's `uid` is then compared, `buffersAreEqual(existingRecord.uid, uid)`; `reachableByFlows`
  stitches the two comparison **co-operands** together, jumping onto the independent parameter `uid`.
- The fields actually serialized are `uidStr = String(uid)` where `uid = sessionToken.uid` (an
  authenticated session id, not the request payload) and `secret = random.hex(16)`.

So the attacker's input influences a lookup key and a control decision, but never a serialized field.
Raw data-dependence reachability positively *misled* the adjudicator. This example is kept as a
first-class result: it is the evidence that reachability is insufficient, and it motivated
property-specific propagation as a distinct layer rather than a tweak to the taint query.

---

## 3. Security-property propagation

### 3.1 Two independent dimensions per edge

Every edge on an established path is classified along two axes that are deliberately **not**
conflated:

- **structural_relation** — how the value moves in the CPG: `VALUE_PRESERVING_FLOW`, `PROPERTY_READ`,
  `ARGUMENT_TO_PARAMETER`, `VALUE_TRANSFORM`, `LOOKUP_KEY_INFLUENCE`, `CONTROL_DEPENDENCE`,
  `RETURN_VALUE_DEPENDENCE`, `RECEIVER_OR_ARG_ARTIFACT`, `ARG_INTO_SINK`.
- **property_effect** — whether *attacker control of serialized size/structure* survives the edge:
  `PRESERVES_PROPERTY`, `TRANSFORMS_PROPERTY` (value changes but size-influence survives, e.g.
  `toLowerCase`), `BREAKS_PROPERTY`, `PASS_THROUGH` (structural noise), `UNKNOWN` (needs review).

Keeping these separate is what lets `structural_relation = LOOKUP_KEY_INFLUENCE` carry
`property_effect = UNKNOWN` rather than being forced to a verdict by its structural label.

### 3.2 The decisive breaks, and the honest UNKNOWNs

Only two structural situations are treated as *definite* breaks of the size property: a comparison
co-operand stitch (`CONTROL_DEPENDENCE`, the exact emails.js artifact) and a confirmed bounding
builtin such as `slice(0, 32)`. Lookups and black-box returns are **UNKNOWN**, not breaks: their
size-provenance is genuinely undetermined, so they route to semantic review rather than being
silently rejected. An UNKNOWN effect is never treated as preserving *or* as breaking.

### 3.3 The frozen lattice

Single alternative (edges composed left to right along one source→sink path):

    PRESERVES + PRESERVES           -> PRESERVES
    PRESERVES + TRANSFORMS          -> PRESERVES     (attacker size-influence survives)
    <anything> + BREAKS             -> BROKEN        (a definite break dominates)
    <anything> + UNKNOWN (no break) -> OPEN          (UNKNOWN is INFECTIOUS along the path)

Across alternatives and origins (existential — one survivor is enough):

    any ESTABLISHED -> ESTABLISHED; else any OPEN -> OPEN; else any BROKEN -> BROKEN; else NO_FLOW

Three outcomes are kept scientifically distinct and must never be collapsed:

- **NO_FLOW** — no structural relation at all.
- **BROKEN** — a relation existed, but the property was demonstrably destroyed.
- **OPEN** — a relation existed, but the property semantics are insufficiently modeled (→ review).

with **ESTABLISHED** meaning the property is preserved to the sink.

### 3.4 Boundary pressure-test

Eight boundary fixtures plus the real candidates behaved correctly with no per-case tuning:

| case | outcome |
|---|---|
| `JSON.stringify(req.body)` | ESTABLISHED |
| `req.body.name.toLowerCase()` | ESTABLISHED (TRANSFORMS) |
| `req.body.name.slice(0,32)` | BROKEN (bounding) |
| constant replacement / index lookup | NO_FLOW |
| `db.get(req.body.id).userSuppliedBlob` | OPEN (lookup; id origin not established) |
| comparison co-operand | BROKEN |
| multi-origin (one breaks, one reaches) | ESTABLISHED (surviving origin) |
| emails.js / normalizeEmail | BROKEN → rejected |
| customs.js / sanitizePayload | OPEN → semantic review |

The lookup-returning-stored-data case resolves to OPEN rather than a hard break: the request-id
origin is simply *not established*, so an independently attacker-controlled returned field is never
joined back to the request-id origin. Hard-breaking that pattern globally was deliberately rejected,
because APIs exist where a lookup key does select an attacker-controlled object.

---

## 4. Transform identity: the gap and the second proof

### 4.1 The gap

For a transform on an OPEN path, the adjudicator will only *accept* a semantic answer if it can
independently establish the transform's identity (`subject_transform != UNKNOWN`). The existing
identity mechanism is an import-based definition resolver — and a corpus characterization showed it
identifies almost nothing in method-heavy code: **0 of 565** transform calls in `customs.js`, **11 of
536** in `fxa-shared`. Most transform calls are `this.`/`obj.` member calls it structurally cannot
resolve. The gap is systematic; its downstream impact in the labeled candidate set was a single
candidate (`customs.js` `sanitizePayload`), but that is a thin-corpus artifact.

Candidates were bucketed: (A) resolver identifies it; (B) resolver UNKNOWN but a unique local callee
body exists; (C) resolver UNKNOWN and multiple bodies share the name; (D) resolver UNKNOWN and no
local body. Only bucket B is bridgeable.

### 4.2 The second identity mechanism

A trace-backed identity proof was added as a *second* mechanism, narrowly scoped by an explicit
invariant:

    transform identity is ESTABLISHED iff either
      (1) the definition resolver establishes it, OR
      (2) the observed call is trace-linked to EXACTLY ONE callee body (via actual MethodParameterIn
          entry on the dataflow path), and that exact body is the body supplied to adjudication.

No same-name inference, no `this.foo()` shortcut, no promotion from the population proxy. Ambiguous
(C) and bodiless (D) calls stay UNKNOWN.

### 4.3 The ambiguity negative control (and what it caught)

A polymorphic control — one call site that could dispatch to two class methods — was the important
safety test. It caught a real weakness: `reachableByFlows` enumerated only *one* of the two targets,
so counting entered bodies alone would have wrongly called the site unique. The frontend, however,
represents the ambiguity in the call's `methodFullName` as a union (`"A | B:transform"`,
`DYNAMIC_DISPATCH`). The producer was hardened to deny identity on *any* CPG-visible ambiguity signal
(union method name, multiple `call.callee` targets, or multiple entered bodies), which also closes
the under-enumeration gap. End-to-end, an identical HIGH-confidence semantic answer resolves the
unique control but *cannot* resolve the ambiguous one — ambiguity blocks promotion downstream, not
just in the producer's label.

A known residual limitation: if the frontend silently *monomorphizes* a genuinely polymorphic call,
this layer cannot detect it. That is a frontend soundness limitation, correctly kept separate from
the identity bridge.

---

## 5. Disposition follows the property layer

A held-out repo exposed that the adjudicator's disposition was re-derived from the transform-property
model rather than from the property layer. A pure direct `JSON.stringify(req.body)` (zero transforms)
fell through to a vacuous `RESOLVED_SAFE`; a candidate with an off-path `cache.set()` transform fell
to a spurious `CANDIDATE_OPEN`. In both, the property layer had already established that attacker
control reaches the sink.

The fix makes disposition consistent with the property layer: an `ESTABLISHED` property becomes
`RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS`, distinct from OPEN (which still routes to review) and not a
hint-based resolution. Strict regression confirmed only ESTABLISHED candidates moved.

Terminology is guarded explicitly: an ESTABLISHED candidate carries a `property_vs_vulnerability`
record stating "modeled security property only (not a confirmed DoS)" and listing the residual
vulnerability-level questions (effective request-size bounds, reachability, repeatability, actual
resource impact). The disposition means the modeled property is established, never that a DoS is
confirmed.

---

## 6. Held-out generalization

The pipeline was frozen and run on repositories not used in development.

**Precision.** Across eight real repos (express, morgan, body-parser, a boilerplate, a proxy
middleware, express-session, sequelize, node-http-proxy), the `req.* -> JSON.stringify` pattern is
niche: frameworks and middleware serialize their own abstractions, and idiomatic apps serialize via
`res.json`. On all non-matching code the pipeline raised no candidates — no false positives from
generalization.

**Property propagation and Step 6.** node-http-proxy's `JSON.stringify(req.body)` (an examples file)
was correctly `ESTABLISHED` and mapped to the confirmed-candidate disposition.

**Trace identity on TypeScript.** In `novuhq/novu` (a TS backend), an idempotency interceptor threads
`request.body` through a member-method transform (`this.hashRequestBody`) into a serialization sink.
Trace-backed identity generalized: `hashRequestBody` was uniquely trace-identified exactly as
`sanitizePayload` had been. The inner `JSON.stringify(body)` (the hash input) was correctly
`ESTABLISHED`.

**A distinct failure mode.** The outer sink there resolved to `BROKEN` — but via a spurious
`reachableByFlows` path that leaves the hash chain, stitches `bodyHash -> err`, and breaks at an
error-handling comparison, rather than via the hash bound. The verdict (reject) was coincidentally
correct, but the intended OPEN → review path was pre-empted. This is a path-**enumeration**
limitation, not a property-layer defect: the comparison-break rule fired correctly, just on a
spurious edge. It is explicitly kept separate from the identity gap and did not trigger a
property-layer redesign.

**Closing the OPEN branch cleanly.** Because real handlers wrap transforms in control flow, a
controlled held-out isolation (a realistic audit-cache write of a request body through a member
method, no nearby branch) was used to exercise the OPEN branch in both directions, on TypeScript,
through the frozen pipeline:

| variant | property | trace | subject_transform | packet body | answer | disposition |
|---|---|---|---|---|---|---|
| PRESERVES (`redactSecrets`, `{...body}` minus keys) | OPEN | UNIQUE | TRACE-established | exact body | UNSAFE | RESOLVED_CANDIDATE_BY_ACCEPTED_HINT |
| BREAKS (`digestBody`, sha256) | OPEN | UNIQUE | TRACE-established | exact body | SAFE | RESOLVED_SAFE_BY_ACCEPTED_HINT |

The identity/body handoff was then asserted explicitly rather than inferred from the disposition:
`property_open_edge.call_node == trace_identity.call_node == adjudication.subject_call_node`, and, per
variant, the body supplied to adjudication equals the body emitted for the uniquely identified callee
and *is* that callee's definition. Both assertions initially **failed** — a call-node mismatch, then a
missing body in the packet — and those failures are preserved as evidence the correspondence was
tested. The second failure was a genuine Step 4 integration bug: the relevant-code inclusion checked
`def_status == "ESTABLISHED"` while trace identity sets `"ESTABLISHED_BY_TRACE"`, so the exact body
never reached the semantic packet. Fixing the check completed the Step 4 invariant end-to-end.

---

## 7. Exploitability adjudication of the strongest real candidate

The final question was not "does the pipeline work" but "does an ESTABLISHED real candidate survive
the vulnerability-level checks into a true positive." The novu interceptor was adjudicated against the
four residuals:

- **Size bound.** Most routes get body-parser's ~100kb default, but `extendedBodySizeRoutes`
  (including the core POST `/v1/events`) get a **20mb** limit. Attacker-controlled serialized size is
  up to 20MB, not 100kb.
- **Reachability.** The interceptor is a global `APP_INTERCEPTOR` on POST/PATCH; the serialize+hash
  runs only with an `idempotency-key` header (attacker can supply it), the feature flag on (not
  attacker-controlled), and valid auth.
- **Repeatability.** Yes.
- **Resource impact.** `JSON.stringify` plus blake2s256 over an ≤20MB body per request, on top of
  baseline; amplifiable by concurrency but capped at 20MB.

**Verdict: conditional true positive, low/moderate severity.** It survives all four checks as a real
serialize-amplification surface on POST `/v1/events`, but is downgraded from a critical DoS by the
authentication requirement, the feature-flag gate, client opt-in, and the 20MB cap. No proof-of-
concept is included; the appropriate follow-up is a responsible maintainer report with these
conditions and load-testing to quantify the amplification. The node-http-proxy candidate, equally
ESTABLISHED at the property level, is a vulnerability-level *false positive* (examples file, ~100kb
default) — exactly the property-vs-vulnerability distinction the terminology safeguard preserves.

---

## 8. Contributions

1. **Security-property propagation as a distinct adjudication layer** between structural reachability
   and semantic review, with `structural_relation` and `property_effect` kept separate and an explicit
   lattice whose UNKNOWN is infectious and whose NO_FLOW / BROKEN / OPEN outcomes stay distinct.
2. **The reachability-is-insufficient result** (emails.js), demonstrated on real corpus code, as the
   architectural justification rather than an assumption.
3. **A narrowly-scoped trace-backed identity proof** that promotes trace evidence into a legitimate
   identity mechanism only for a unique, non-ambiguous, trace-entered callee whose exact body is
   supplied to adjudication — with a negative control proving ambiguity blocks promotion.
4. **A disposition layer that follows the property layer**, with an explicit property-vs-vulnerability
   boundary so an established property is never over-read as a confirmed vulnerability.
5. **A frozen held-out evaluation** showing the classification, identity, and disposition generalize
   to unseen JavaScript and TypeScript, and surfacing two honest failure modes — a spurious path
   enumeration and a packet-delivery bug — the first documented, the second fixed.
6. **One end-to-end true positive** carried from an ESTABLISHED property through exploitability
   adjudication, with a real-repo false positive alongside to show the residual checks discriminate.

---

## 9. Limitations and future work

- **Path enumeration can dominate correctness.** `reachableByFlows` may enumerate a single spurious
  path (a cross-variable stitch) and miss the legitimate one. The property layer classifies whatever
  path it is handed correctly, so the leverage point is enumeration, not classification. Quantifying
  how often the enumerated path is spurious is the most valuable next study.
- **Frontend soundness.** If jssrc2cpg monomorphizes a genuinely polymorphic call, the identity layer
  trusts the frontend's call graph and cannot recover the hidden ambiguity.
- **Pattern niche.** The `req.* -> JSON.stringify` surface is uncommon in idiomatic code; the pipeline
  is precision-oriented and yields many correct nulls.
- **Vulnerability level is empirical.** Establishing the modeled property is static; confirming a DoS
  requires load-testing and threat-model context that sit outside the static core.
- **Corpus size.** The labeled candidate set is thin; broader held-out evaluation across more
  backends (especially TypeScript services with genuine member-method transforms straight to sinks)
  would strengthen the generalization claims.

---

## 10. Reproducibility

The pipeline is a set of frozen Joern/Scala producers (source facts, propagation, definition
resolution, path context), the security-property propagation producer, the trace-backed identity
producer, and a Python adjudicator. Each held-out result above was produced by running the frozen
pipeline without per-case tuning; the accompanying packages contain the producers, the per-candidate
fact tables, the fixtures, and the assertion scripts used to verify the identity/body correspondence.
