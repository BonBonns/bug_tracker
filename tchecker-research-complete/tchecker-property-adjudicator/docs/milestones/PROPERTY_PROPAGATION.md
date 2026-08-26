# Security-property propagation — from "does taint continue?" to "does the property survive?"

The complete code-bearing packet exposed that the emails.js/normalizeEmail serialize-DoS
candidate is a false positive, and — more importantly — that the gate should not ask whether
generic taint continues, but whether the *specific security property* the candidate depends on
survives each edge. For serialize-DoS that property is
**ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE**.

## Two independent dimensions per edge (never conflated)
`export_property_propagation.sc` classifies every edge of an established path with:
- **structural_relation** — how the value moves in the CPG: VALUE_PRESERVING_FLOW, PROPERTY_READ,
  ARGUMENT_TO_PARAMETER, VALUE_TRANSFORM, LOOKUP_KEY_INFLUENCE, CONTROL_DEPENDENCE,
  RETURN_VALUE_DEPENDENCE, RECEIVER_OR_ARG_ARTIFACT, ARG_INTO_SINK.
- **property_effect** — whether the security property survives: PRESERVES_PROPERTY,
  TRANSFORMS_PROPERTY (changed but attacker size-influence survives, e.g. toLowerCase),
  BREAKS_PROPERTY, PASS_THROUGH (structural noise), UNKNOWN (needs semantic review).

An UNKNOWN property effect is never silently treated as preserving — nor as breaking. The only
**definite structural breaks** are a comparison co-operand stitch (CONTROL_DEPENDENCE) and a
confirmed bounding builtin such as `slice(0, 32)`. Lookups and black-box returns are UNKNOWN,
not breaks: their size-provenance is genuinely undetermined, so they go to semantic review.

## Per-origin outcome and candidate rollup
Each source→sink alternative yields BROKEN (a BREAKS edge before the sink), OPEN (no break but a
property-UNKNOWN transform on the path), or ESTABLISHED (preserved/transformed-but-preserved to
the sink). The candidate outcome is the **best surviving alternative** (ESTABLISHED > OPEN >
BROKEN), so a candidate with one broken origin and one genuine origin stays established.

## Boundary pressure-test (8 cases) + 3 real candidates
| case | property outcome |
|---|---|
| `JSON.stringify(req.body)` | ESTABLISHED |
| `JSON.stringify(req.body.name.toLowerCase())` | ESTABLISHED (TRANSFORMS_PROPERTY) |
| `JSON.stringify(req.body.name.slice(0,32))` | BROKEN (bounding) |
| `JSON.stringify(normalize(req.body))` constant | no flow (property cannot propagate) |
| `JSON.stringify(table[req.body.key])` | no flow |
| `db.get(req.body.id).userSuppliedBlob` | OPEN (semantic review) |
| `record.uid === session.uid; JSON.stringify(session.uid)` | BROKEN (comparison) |
| multi-origin (one breaks, one reaches) | ESTABLISHED (surviving origin) |
| **emails.js / normalizeEmail (FxA)** | **BROKEN → REJECTED** |
| **customs.js / sanitizePayload** | **OPEN → semantic review** |
| **fixture clip/wrap** | **OPEN → resolved by hint** |

The lookup-returning-stored-data case resolves to OPEN rather than a hard break: without table
facts a lookup's size-effect is honestly unknown. The critical requirement still holds — the
request-id origin is *not established*, so an independently attacker-controlled returned field is
never joined back to the request-id origin.

## emails.js: why it is a false positive
Attacker value is live `request.payload → email → normalizeEmail → normalizedEmail`, then the
path crosses `db.getSecondaryEmail(normalizedEmail)` (lookup) and, decisively,
`buffersAreEqual(existingRecord.uid, uid)` — a comparison whose co-operand `uid` is stitched in
by reachableByFlows. The serialized fields are `uidStr = String(uid)` with `uid =
sessionToken.uid` (authenticated session, not request.payload) and `secret = random.hex(16)`.
The comparison edge is a definite BREAKS_PROPERTY, so every origin is BROKEN → the candidate is
rejected and the LLM is never asked whether normalizeEmail bounds size.

## Validity gate (adjudicator)
The adjudicator consumes `property_outcome.tsv`: BROKEN → REJECTED_FALSE_POSITIVE (no question);
OPEN → semantic review; ESTABLISHED → property confirmed; absent → NOT_AUDITED (no change). No
frozen producer was modified. Verified: fixture RESOLVED_CANDIDATE_BY_ACCEPTED_HINT (unchanged),
customs.js CANDIDATE_OPEN (2 questions), emails.js REJECTED (0 questions).

## Where this lives in the architecture (terminology)

The frozen structural/dataflow producers (`export_sourcefact.sc`, `export_propagation.sc`,
`export_definition_resolver.sc`, `export_path_flow_context.sc`, ...) are unchanged. Security-
property propagation is a **new layer inserted between those producers' output and the
adjudicator** — it is not one of the frozen structural producers and does not modify them:

    frozen structural / dataflow producers  (reachability, definitions, path facts)
        |   (source_facts.tsv, definition_resolution.tsv, ...)
        v
    property-propagation LAYER  =  export_property_propagation.sc
        - edge classification (structural_relation, property_effect)
        - single-alternative composition + existential join over alternatives
        |   (property_propagation.tsv, property_outcome.tsv)
        v
    adjudicator  =  adjudicate_js.py
        - existential join over ORIGINS per sink -> candidate outcome -> disposition

The lattice therefore lives in the property-propagation layer (per-alternative composition and
alternative join) and the adjudicator (origin join) — never in the frozen structural producers.

## Frozen lattice semantics (explicit, so future work cannot reinterpret OPEN as weak preservation)

**Single alternative** (edges composed left-to-right along ONE source→sink path):

    PRESERVES + PRESERVES           -> PRESERVES
    PRESERVES + TRANSFORMS          -> PRESERVES        (attacker size-influence survives)
    <anything> + BREAKS             -> BROKEN           (a definite break dominates)
    <anything> + UNKNOWN (no break) -> OPEN             (UNKNOWN is INFECTIOUS along the path)

So a single alternative is BROKEN if any edge BREAKS; else OPEN if any edge is UNKNOWN; else
ESTABLISHED. UNKNOWN is infectious: once an alternative touches an unmodeled edge it can be at
best OPEN, never silently upgraded back to preservation by later edges.

**Across alternatives / origins** (existential — one survivor is enough):

    any ESTABLISHED alternative -> ESTABLISHED
    else any OPEN alternative    -> OPEN
    else any BROKEN alternative  -> BROKEN
    else                          -> NO_FLOW

This existential join is what lets the multi-origin candidate survive: one origin broken at a
lookup does not kill another origin that genuinely reaches the serialized data.

**Three outcomes that must never be collapsed:**

| outcome | meaning | adjudication |
|---|---|---|
| NO_FLOW | no structural relation at all | REJECTED_NO_STRUCTURAL_FLOW |
| BROKEN  | relation existed, property demonstrably destroyed | REJECTED_FALSE_POSITIVE |
| OPEN    | relation existed, property semantics insufficiently modeled | semantic review |
| ESTABLISHED | property preserved to the sink | confirmed |

The field-extraction heuristic ("field read from the return of an unentered call whose argument
was only a lookup key ⇒ BROKEN") is deliberately NOT added: there are real APIs where a lookup
key selects an attacker-controlled object, so hard-breaking that pattern globally would create
false negatives. c6 therefore resolves to OPEN, and the candidate rule (an origin establishes
only through a fully surviving path) means the id origin is never spuriously established.

## Pipeline thesis
    Joern reachableByFlows
      → structural / data dependence
      → TChecker security-property propagation   (this layer)
      → security-relevant path
      → LLM only if the property remains UNRESOLVED

The earlier pipeline treated "source can reach sink in the DDG" as too close to "the source's
dangerous property reaches the sink." The FxA example proves those are not equivalent.

### Negative result (thesis material)
A real-corpus candidate initially appeared to form an HTTP-input-to-serialization path.
Rendering the complete path and code context revealed that the attacker-controlled email was
used only as a database lookup key, and the value later serialized was derived from an
independent authenticated-session identifier and a random secret. This exposed a limitation of
raw data-dependence reachability and motivated property-specific propagation as a distinct
adjudication layer between structural reachability and semantic (LLM) review.
