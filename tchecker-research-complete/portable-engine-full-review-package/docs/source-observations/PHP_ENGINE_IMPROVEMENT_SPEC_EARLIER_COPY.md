# Next-Engine Improvement Spec

Design instructions for a rebuilt/optimized engine. Each item states **what to change**, **why it's justified** (measured evidence, not speculation), and **how to verify it**. Ordered by expected value.

Ground rule inherited from this project: *nothing here is a claim about what will work — every item names the measurement that would confirm or kill it.* Several previously "obvious" improvements were measured and rejected; those are in §10 so they don't get rebuilt.

---

## P0 — Highest value, evidence already in hand

### 1. Remove the hard recursion depth cap; make traversal budget adaptive

**Current:** `node.caller.size() >= 9` silently declines to enter deeper flows. No log, no record, no unresolved marker — the flow simply never happens.

**Evidence:** instrumented count on GiveWP = **848 truncation events across 43 distinct call sites**; 0 on Smush and Rank Math. Depth-dependent, not universal. Every one of the 848 is a candidate false negative that the engine currently cannot even report.

**Do instead:**

- Replace the constant with a configurable budget, default well above 9.
- **When the budget is hit, emit a record** (`TRUNCATED_DEPTH`, with the site and depth) rather than returning silently. A truncated flow must be *visible* — silent truncation is the worst failure mode because it's indistinguishable from "no flow exists."
- Prefer a **global work budget** over a per-path depth constant: cost concentrates in a few sites (43 sites produced all 848 hits), so a flat depth cap penalizes shallow-but-wide analysis to pay for a handful of deep ones.

**Verify:** raise the cap, re-run the seven corpora, diff finding sets. New findings must be adjudicated on sink-side safety (§9). If nothing appears, the cap was harmless and you've retired a suspicion cheaply.

### 2. Sanitizers must be class-scoped, not a flat set

**Current:** a flat `Set<String> sanitizers`. This is the **wrong shape** and is the single biggest architectural blocker to porting off WordPress.

**Why:** sanitizer semantics are **sink-class-specific**. `esc_sql()` does nothing for XSS; `esc_html()` does nothing for SQL; `esc_attr()` vs `esc_html()` differ *within* XSS by output context. A flat set cannot express any of this and will silently accept a wrong-context escape as safe.

**Do instead:** model sanitizers as a relation `sanitizer × sink_class × output_context → adequacy`, with classes at least `SQL`, `XSS_HTML_BODY`, `XSS_ATTRIBUTE`, `XSS_JS_CONTEXT`, `XSS_URL`, `PATH`, `SHELL`. Build this into the core type from day one — retrofitting it was already identified as painful here.

**Verify:** a fixture matrix of (sanitizer × sink context) where wrong-context pairs must still fire.

### 3. Taint propagation must be semantic, never syntactic

**Current bug class:** `argsContainSource()` searched the argument *subtree* for a source node. Taint arriving via another function's **return** lives in the interprocedural summary, not in the argument's AST — so it vanished silently. `trim($_GET['x'])` fired; `trim(get_tainted())` did not.

**Do instead:** the "does this expression carry taint" predicate must consult **abstract value state** (return summaries, derived provenance), never AST shape. Treat any syntactic membership test as a design smell.

**Note:** this is **not** WordPress-specific — it affects any wrapper composing over a tainted call return, and should be assumed present in any ecosystem port.

### 4. Sanitization checks must be structure-aware

**Current bug class:** the taint predicate tested source membership over a **flattened** subtree, so it could not see wrapping. `f()` returning `esc_html($_GET['x'])` was treated as a tainted return.

**Do instead:** evaluate sanitization by walking the **enclosing structure** from source to sink, not by set-membership over flattened nodes. One shared definition of "sanitized" — this project had to actively resist introducing a second, drifting one.

### 5. Model persistence boundaries (stored / second-order taint)

**Why:** the most valuable finding in this project (the Elementor/GiveWP stored-XSS candidate) flows **write → post meta → later read → render**. That is a second-order flow. The engine found it only incidentally, via §3's fix, not because it models persistence.

**Do instead:** treat storage APIs as explicit **sink-and-source pairs** (`update_post_meta`/ `get_post_meta`, options, user meta, transients, DB rows). A write of tainted data is a *persistence event*; a read of the same key is a *source* with provenance pointing at the write.

**Verify:** the GiveTotalsWidget case should be discoverable *by design* rather than as a side effect.

---

## P1 — Structural improvements

### 6. Output context must be first-class, including sub-lexical contexts

**Evidence:** verified experimentally against the real WordPress 6.7.1 shortcode parser. Payload `1"]<script>alert(1)</script>[give_totals ids="2` **reaches output**, while ordinary attribute injection `1" onmouseover=` **fails**. Same sink, same variable — different escape mechanics.

**Implication:** a value interpolated into a *shortcode attribute inside a string that is later re-parsed* is not in "HTML attribute context." It's in a **nested parser context**, and the relevant question is whether the payload can **break the enclosing bracket structure**.

**Do instead:** model output context as a stack of parsers the value passes through (PHP string → shortcode parser → HTML), and evaluate escape adequacy at **each** layer. Any engine that flattens this to "attribute context" will misjudge both directions.

### 7. Implement the full relation/evidence model up front, with abstention

**Current history:** only one of four relation kinds was ever implemented; the guard (`instanceof CallExpressionBase`) silently excluded `echo` sinks, so **every echo sink** fell to a generic fallback regardless of how well the value was tracked. The lineage was already being computed into a sidecar nobody read.

**Do instead:**

- Implement all relation kinds together; a missing branch is invisible as a bug and looks like "evidence unavailable."
- Keep **explicit abstention** as a first-class outcome. Measured here: 42/47 sinks had a unique defining assignment, 5 had competing definitions. For those 5, naming either would fabricate a claim. Abstention is a feature, not a fallback.
- **Evidence strength ≠ verdict.** `VALUE_SPECIFIC` means "we identified which value flows here," not "this is vulnerable." Downstream consumers must not be able to confuse the two — enforce it in the type, not in prose.

### 8. Origin resolution needs a state-channel model, and return-relevance is mandatory

**Measured:** the flagship known-positive cluster's true origin is `Give()->session->get('give_purchase')['post_data']` — an unmodelled cross-request session channel. `NOT_ESTABLISHED` there is **correct**, not a defect. Ordinary dataflow has been followed as far as it goes.

**Two instructions:**

- Model session/request-state channels explicitly. This is the actual gap, and it's a *modelling* problem, not a deeper-dataflow problem.
- **If you build any interprocedural origin bridge, require return-relevance.** Attributing origin because a callee merely *contains* a source is wrong: measured 5 true / 9 false on return relevance, and **none** of the flagship positives were return-relevant. The naive bridge would have stamped a bogus `$_GET['form-id']` origin (a guard-only value, compared and discarded) onto the four most important findings — strictly worse than admitting `NOT_ESTABLISHED`.

### 9. The adjudication layer must consume engine evidence

**Current:** the deterministic path **structurally cannot** use value provenance — the field is read only on the LLM path. So all evidence-quality work was invisible to deterministic verdicts.

**Do instead:** define the engine→adjudicator interface as a **typed contract** (relation kind, identity precision, origin status, context stack, truncation flags) and make the deterministic path consume it. Also inherit these adjudication rules, which were established the hard way:

- Judge on a **concrete sink-side safety mechanism** at the exact output context.
- `NOT_ESTABLISHED`, "admin-only", "author-controlled", and "requires privileged role" are **not** false-positive criteria.
- Conditional sanitizers need type-guard reasoning: \`is\_scalar(v)?sanitizetextfield(v) ? sanitize\_text\_field( v)?sanitizet​extf​ield(v) : $v\` is **not** a sanitizer — the else branch returns raw. Wrappers must be recognized only when *every* return path is trusted.

---

## P2 — Performance and engineering hygiene

### 10. Known hot spots and cheap wins

- **Hash lookups, not linear scans.** A confirmed case did three sequential `keySet()` scans with `String.equals()` where `.get()` was exactly equivalent — measured 84,627 calls / \~32s cumulative. Audit for this pattern generally.
- **`LinkedList.contains()`** **O(n)** inside graph/CSV export showed up in live stack sampling.
- **Boxed** **`Long`** **identity comparison.** Code compares boxed `Long` with `==`. Instrumented divergence was **0 across 2601 calls** — currently latent, so fix it for correctness, but do **not** expect a detection win.
- **Defensive copying.** Caller stacks are aliased rather than cloned; measured **0 mutations across 73,323 aliased assignments** — also latent. Same guidance: correctness, not results.
- Prefer **live stack sampling** over static inspection to find real hot spots; it repeatedly found costs that static reading missed. Report it honestly as sampling ("appeared in 2 of 6 samples"), not as a percentage of runtime.

### 11. Build the measurement harness into the engine, not beside it

Non-negotiable, all learned from failures here:

- **A completion marker.** Emit `ANALYSIS_STATUS=COMPLETE` and treat *only* that as evidence a run finished. Partial output looks identical to success.
- **Structured findings output.** Machine-diffable finding IDs so A/B is a set diff, not log grepping. Human-readable logs hit \~600MB per run here and filled the disk.
- **Shadow-instrumentation as a standard pattern.** New behaviour ships behind a counter that measures divergence from current behaviour with **zero behaviour change**, and only then gets promoted. This pattern is what proved 2 of 3 suspected bugs were latent.
- **Gate convention.** One documented registry of experimental flags; verify a flag is actually read on the production path. Flags here were repeatedly found to be dead, inert, or never executed.
- **Corpus A/B as a first-class command**, not an ad-hoc script.

---

## 12. Do NOT rebuild these — measured and rejected

| IdeaWhy it's dead                                  |                                                                                                                                                                          |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Naive interprocedural origin bridge                | Would assign bogus origins to the flagship positives; only \~6% addressable, and 0 high-value cases survive a return-relevance filter                                    |
| Chasing `NO_DEFINING_ASSIGN` (50% of unresolved)   | The bug bucket is **empty**; it is correct abstention (44% have no local assignment, 38% are direct call results)                                                        |
| Recognizing `give_clean()` as a sanitizer          | Its else branch returns raw; seven FPs attributed to it rest on a false premise                                                                                          |
| Minimal fixtures for unresolved-attribution states | Five attempts failed. Simple fixtures get fully resolved; disconnected ones lose propagation. Validate this class against a real corpus with a pre-measured blast radius |

---

## 13. Process rules that earned their place

- **Measure before building.** Three diagnostics, one corpus run each: one validated a feature, one killed a feature that looked good twice, one proved the biggest apparent problem was correct behaviour.
- **A silent code path is worse than a wrong one** — it's unfalsifiable. Every abstention, truncation, and unresolved state must be *emitted*.
- **Keep findings labeled "candidate" until runtime-confirmed.**
- **Blinded external review is a real QA layer.** It caught a genuine adjudication error here that self-review missed.
- **Distrust confident intermediate readings, including your own.** In this project every one of six confident factual errors was caught by an empirical check and none by re-reading the reasoning. Build the engine so checks are cheap, because they are what actually holds.