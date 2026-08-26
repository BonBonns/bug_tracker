# JS-STATE-R09 — Bug-Family Re-Scoping Characterization

**Characterization only. Nothing was implemented.** R07 was not modified
(hash unchanged). No `ComparisonCoercionFact` was built, no operator was added
to any closed set, no exception semantics were introduced.

Central question: **which of the three candidate families has enough
real-world support to justify being a first-class Fable bug family?**

---

## Evidence summary across all prior milestones

### Family A — EXPLICIT_STATE_ERASURE (R07's current model)

```text
result -> Number/String/Boolean/parseInt/template/bitwise -> later failure guard -> sink
```

| | |
|---|---|
| Synthetic positives | **YES** — 5-case fixture, `JS_STATE_R07=31/31`, four-way isolation matrix proven |
| Real-world positives found | **0** |
| Real corpora tested | **3** (mozilla/fxa 77,966 LOC; node-oauth2-server 3,859 LOC; tarkov-data-manager 2,207 LOC incl. a known CVSS 9.8 auth bypass) |
| Real false positives | 1 (FxA), correctly eliminated by R07 for the demonstrated reason |
| Detector soundness | Not in question — R07 behaves exactly as specified on every case it was given |
| Known structural limit | Signal B is TypeScript-dependent (R08): failure-capable union hints measured fxa=present, node-oauth2=11, tarkov=**0** |

**Status: `SUPPORTED_LOW_BASE_RATE`.** This is deliberately *not* "failed."
R07 is a sound detector for a pattern that the real-world sample does not
exhibit often enough to justify centrepiece status. That distinction is the
thesis-relevant result, not a defect.

### Family B — IMPLICIT_COMPARISON_COERCION

```text
left operand, right operand -> <operator>.equals -> ECMAScript abstract-equality
coercion -> comparison result -> authentication/authorization decision
```

| | |
|---|---|
| Confirmed historical vulnerability | **YES** — CVE-2026-21854 / GHSA-r8w6-9xwg-6h73 (CVSS 9.8) |
| Vulnerable/fixed replay available | **YES** — `188f7562` -> `f188f0ab`, both extracted and scanned in R08 |
| Real security consequence | **YES** — unauthenticated full admin access with valid session cookie |
| Source-verified mechanism | **YES** — read from the actual vulnerable commit, not advisory prose |

Family B is the only family with a real, replayable, source-confirmed
positive anchor.

### Family C — EXCEPTION_STATE_HANDLING

| Corpus | `throw new …Error` | `catch` |
|---|---|---|
| mozilla/fxa (`lib/{routes,tokens,crypto,oauth}`) | 169 | 294 |
| node-oauth2-server (`lib/**`) | 157 | 9 |
| tarkov-data-manager (`index.mjs`) | 3 | 41 |

| | |
|---|---|
| Base rate in real JS/TS | **HIGH** — dominant failure idiom in all three corpora, without exception |
| Confirmed analogous vulnerability | **NOT ESTABLISHED** — no CVE of an exception-state-erasure shape has been source-confirmed in this work |
| Model coverage today | None. Deliberately parked as `EXCEPTION_FAILURE_IDIOM` since R02 |

Family C has by far the highest base rate and by far the weakest security
evidence. High base rate alone is not a reason to build a detector — it is a
reason to *characterize* whether a security-relevant erasure shape even exists
in that idiom.

---

## Family B characterized properly (the R09 core)

A dedicated fixture (`fixture/family_b.ts`) was built with the CVE as positive
anchor plus five negative controls, and run through the real frontend. The
five evidence components the brief specifies were each measured.

### Measured: `COMPARISON_OPERATOR` — **NOT AVAILABLE**

This is R09's decisive finding.

`jssrc2cpg` exports **`==` and `===` as the identical CPG node**:

```text
name=<operator>.equals | mfn=<operator>.equals | typeFullName=ANY | code=users[username] == password
name=<operator>.equals | mfn=<operator>.equals | typeFullName=ANY | code=users[username] === password
```

`name`, `methodFullName`, and `typeFullName` are all identical. Verified by
querying Joern directly, not merely by reading our own TSV export — so this
is a **`FRONTEND_GAP`**, not something our normalizer discards.

The consequence is severe and specific: **B1 (the CVE) and B2 (its official
fix) are completely indistinguishable in the current fact set.** The entire
security content of CVE-2026-21854's patch is a one-character-pair change that
Fable currently cannot observe. A Family-B detector built on today's facts
would either flag both or flag neither.

The only place the distinction survives is the raw `code` string. Recovering
it by parsing that string is *possible* but is a **lexical** recovery, not a
semantic graph fact, and is fragile in ways that matter (`a == b === c`,
`==` inside string literals, the enclosing `logicalAnd` node whose `code`
contains both operands' text). It is recorded here as a disclosed fallback,
explicitly **not** recommended as the sound path — the sound fix is at the
frontend/CPG level.

### Measured: `LEFT_TYPE_DOMAIN` / `RIGHT_TYPE_DOMAIN` — **PARTIALLY AVAILABLE, and better than expected**

| Case | Left operand type | Right operand type | Domain relation |
|---|---|---|---|
| B1 (CVE anchor) | `ANY` | `__ecma.String` | not proven same |
| B2 (`===` fix) | `ANY` | `__ecma.String` | not proven same *(identical to B1)* |
| B3 (same-type control) | `__ecma.String` | `__ecma.String` | **proven same** |
| B4 (`== null` idiom) | `string \| __ecma.Null \| ANY` | `__ecma.Null` | **null-idiom, identifiable** |
| B5 (`== 0`, non-security) | `__ecma.Number` | `__ecma.Number` | **proven same** |
| B6 (cross-domain probe) | `…externalLookup:<returnValue>` | `__ecma.String` | not proven same |

This is genuinely encouraging for FP suppression:

- **B3 and B5 are cleanly excludable** — both operands provably share a type
  domain, so abstract-equality coercion is inert regardless of operator.
- **B4, the critical unusability risk, is cleanly identifiable** — the right
  operand's type is literally `__ecma.Null`, so the deliberate
  `x == null` null-or-undefined idiom can be recognized and suppressed
  structurally, *without* resorting to source-text matching. This directly
  answers the concern that a generic "`==` is dangerous" detector would be
  unusable.
- **B1/B6 land in "not proven same domain"** — which is correctly *not* the
  same as "proven different." `ANY` means unknown. Under Fable's standing
  invariant (UNKNOWN is not SAFE, and equally not PROOF), `ANY` vs `String`
  is weak positive evidence at best.

### Measured: `COERCION_SEMANTICS` — **NOT DERIVABLE**

Follows directly from the operator gap: without knowing whether the operator
is `==` or `===`, whether ECMAScript abstract-equality coercion occurs at all
cannot be established. This is not a separate gap; it is the operator gap's
consequence.

### Measured: `SECURITY_DECISION_USE` — **AVAILABLE**

Reuses the existing R03 sink-reachability mechanism unchanged (REF-based,
name-independent, profile-driven). Already proven across R03/R04/R05/R07. No
new work needed here.

### Family B evidence scorecard

| Component | Status |
|---|---|
| `LEFT_TYPE_DOMAIN` | PARTIAL (good enough to exclude B3/B5, identify B4) |
| `RIGHT_TYPE_DOMAIN` | PARTIAL (same) |
| `COMPARISON_OPERATOR` | **BLOCKING GAP — `==` / `===` collapsed by frontend** |
| `COERCION_SEMANTICS` | NOT DERIVABLE (consequence of the above) |
| `SECURITY_DECISION_USE` | AVAILABLE (existing mechanism) |

### Family B false-positive risks (characterized, not speculated)

1. **`x == null` idiom** — the single largest usability risk. *Mitigable*:
   structurally identifiable via the right operand's `__ecma.Null` type (B4).
2. **Same-domain `==`** — benign. *Mitigable*: both operand types resolve and
   match (B3, B5).
3. **`ANY` operands** — the dominant residual risk. `ANY` is extremely common
   in real JS (B1's own left operand is `ANY`), and "one operand is `ANY`"
   would match an enormous number of benign comparisons. Requiring
   "not proven same domain" as *positive* evidence would be far too weak a
   bar — this is precisely the R06/R07 lesson (positive evidence only, never
   absence-of-evidence) applied to a new family.
4. **Security-relevance gating** — B5 confirms that coercion-possible sites
   without a security decision must not be flagged; the existing sink profile
   handles this.

---

## Family comparison and decision

```text
BUG FAMILY A — explicit state erasure
  real positive support:        WEAK (0 real positives / 3 corpora)
  synthetic support:            STRONG (31/31, isolation matrix proven)
  semantic evidence available:  YES (implemented and working)
  status:                       SUPPORTED_LOW_BASE_RATE — retain, do not centre

BUG FAMILY B — implicit comparison coercion
  real positive support:        CONFIRMED (1 CVE, CVSS 9.8, replayable pair)
  semantic evidence available:  PARTIAL — type domains yes, OPERATOR NO
  FP risks:                     characterized; the worst (== null) is mitigable
                                structurally; ANY-operand noise is the real risk
  status:                       BLOCKED ON A FRONTEND GAP

BUG FAMILY C — exception-state handling
  base rate:                    HIGH (dominant idiom, all 3 corpora)
  historical security evidence: UNKNOWN (none source-confirmed)
  semantic evidence available:  unmeasured
  status:                       UNCHARACTERIZED
```

### Which family justifies first-class status?

**Family B is the strongest candidate on security evidence — it is the only
family with a real vulnerable→fixed replay — but it is not currently
implementable, and the blocker is not in Fable's analysis layer at all.**

That is a materially different conclusion from "build B next." The honest
ordering is:

1. Family B's blocker is a **single, well-defined, verifiable frontend fact**:
   preserve the `==` / `===` distinction in the CPG. Until that exists,
   *no* Family-B detector can be sound, because the detector could not
   distinguish the CVE from its own patch.
2. Family B's remaining evidence (type domains, sink reachability) is already
   in decent shape, and its worst FP risk (`== null`) is structurally
   mitigable — so once the operator gap closes, B is well-positioned.
3. Family A stays exactly as-is. It is sound, cheap to keep, and its low base
   rate is a finding to report, not a bug to fix.
4. Family C should not be built on base rate alone. High frequency of
   `throw`/`catch` says nothing about whether a *security-relevant erasure*
   shape exists there. That needs its own characterization first, and no CVE
   of that shape has yet been source-confirmed.

---

## Next milestone (nominated only — not implemented)

**JS-STATE-R10 — Comparison-Operator Fidelity (frontend gap closure +
verification).** Narrow and verifiable by construction:

1. Establish whether the `==`/`===` distinction is recoverable from
   `jssrc2cpg` at all (Joern configuration, a different node property, an
   AST-level attribute, or a frontend patch). This is a *measurement*
   question first, not an implementation one.
2. Acceptance test is unambiguous and already built: the R09 fixture's
   **B1 must become distinguishable from B2**. Those two cases are
   byte-identical apart from the operator, so any change that separates them
   is separating exactly the right thing — and any change that does not is
   demonstrably insufficient.
3. Only if (1) succeeds should a `ComparisonCoercionFact` be characterized —
   and even then as characterization first, with the R09 fixture's five
   negative controls as its permanent teeth.

If (1) fails — i.e. the distinction is genuinely unavailable without patching
Joern itself — then Family B is blocked indefinitely, and that outcome should
be reported plainly rather than worked around with source-text parsing.

---

## Thesis-relevant conclusion

R08 and R09 together produce the most transferable result of the JS/TS branch
so far:

> **A synthetically valid detector can still have poor practical value if the
> modelled program idiom has a low real-world base rate.**

R07 is provably correct on every case it was designed for, and has never been
wrong on real code — it simply has almost nothing to find. Discovering that
required the real-corpus phase; no amount of fixture work would have surfaced
it.

R09 adds a second, sharper lesson:

> **Bug-family selection is constrained by frontend fidelity, not only by
> analysis capability.** The family with the best real-world security evidence
> (B) is blocked by a single missing lexical-semantic distinction in the
> frontend, while the family with a complete analysis implementation (A) is
> blocked by base rate. Neither limit is visible from inside the analysis
> layer.
