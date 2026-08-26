# JS-REAL-R02 — Independent Real-Corpus Generalization Test

**No engine changes were made during this milestone.** `js_state_r07.py` and
every upstream module were run at the exact hashes validated in JS-STATE-R07
(verified below). This is a measurement/adjudication pass only.

---

## Phase 1 — Corpus record

- Repository: `https://github.com/node-oauth/node-oauth2-server`
- Commit (frozen before analysis): `42367327a6a832afebf56e0ac6980f0c3e7e4b17`
- Commit date: 2026-07-19 10:04:56 +0200
- Independence from corpus 1: different organization (`node-oauth`, not
  Mozilla), different project, different framework, no shared lineage with
  `mozilla/fxa`. No Mozilla-specific profile or assumption was carried over —
  `security_sink_profile.py` is unchanged and still contains only its generic
  example entry.

### Files

| | count |
|---|---|
| `.js` files (implementation, included) | 38 |
| `.ts`/`.tsx` files (implementation) | **0** |
| Relevant LOC (staged corpus) | 3,859 |

**Included:** `lib/**` (all subdirectories: `errors`, `grant-types`,
`handlers`, `models`, `pkce`, `response-types`, `token-types`, `utils`, plus
`lib/{model,request,response,server}.js`) and the root `index.js`. This is
the entire runtime implementation of the library.

**Excluded, with reasons:**
- `test/` (41 files) — per instruction, scan implementation rather than tests
  first. Also avoids the `.spec.*` frontend-drop issue that dominated FxA's
  Phase 2.
- `index.d.ts` — a pure TypeScript *declaration* file (ambient types only, no
  runtime code, no function bodies). It cannot contain the bug shape (no
  executable guard, transformation, or sink), and including it would inflate
  the "TS file" count misleadingly. Noted explicitly rather than silently
  dropped.
- `docs/`, `package-lock.json`, config/markdown files — non-code.

**Important corpus property, recorded up front:** this corpus is
**100% JavaScript with zero TypeScript implementation files.** That is a
material, deliberate difference from FxA (126 `.ts` / 72 `.js`) and directly
affects Signal B, which reads TypeScript-derived type hints. This is
disclosed here in Phase 1, not discovered later as an excuse.

### Tool/engine versions (unchanged from JS-STATE-R07)

- jssrc2cpg / Joern CLI `4.0.607`, CPG schema `codepropertygraph-domain-classes 1.7.70`
- `export_ts_facts.sc` — `9411e4c7…b02c996f`
- `failure_state_facts.py` — `e5803174…f218e5e`
- `security_sensitive_reachability.py` — `22a4f7ef…00df771`
- `security_sink_profile.py` — `7b760ed9…fd958a8`
- `js_state_r07.py` — `b18bc7aa…6d4d309`

All hashes identical to the JS-STATE-R07-validated versions.

---

## Phase 2 — Frontend validity

| | count |
|---|---|
| Files attempted (filesystem) | 38 |
| Files producing facts (exported) | **38** |
| Files silently absent | **0** |
| Parse failures reported | 0 (`gen.log` empty, exit 0) |
| Methods (internal / external stub) | 177 / 185 |
| Calls | 2,807 |
| Identifiers (with ≥1 REF edge) | 5,575 (4,342 — 78%) |
| Type hints | 1,358 |
| Control structures | 365 |
| Locals / parameters | 1,068 / 982 |
| Closure bindings | 153 |

### Explicit filesystem-vs-exported comparison (per instruction)

A set-difference was computed in **both directions** between the staged
source file list and the distinct files appearing in `methods.tsv`:

```text
IN FILESYSTEM BUT NOT EXPORTED:  (empty)
EXPORTED BUT NOT IN FILESYSTEM:  (empty)
```

**38/38, zero silent omissions.** This is a materially healthier frontend
result than JS-REAL-R01, where `tokens/bundle.js` vanished with no
diagnostic. The check that caught that omission was run again here
specifically so it could not recur unnoticed, and it came back clean.

**Frontend health: GOOD.** No characterization of incompleteness is needed
before interpreting findings.

---

## Phase 3 — R07 chain, run unchanged

| Stage | Count |
|---|---|
| Total calls | 2,807 |
| **Raw ERASES facts** | **0** |
| Sensitive-sink connected | 0 |
| Excluded by R04 (branch) | 0 |
| Excluded by R05 (reassignment) | 0 |
| FAILURE_GUARD_ESTABLISHED | 0 |
| RETURN_CONTRACT_ESTABLISHED | 0 |
| BOTH_ESTABLISHED | 0 |
| **Final candidates** | **0** |
| UNKNOWN return-contract cases | 0 |

**The chain terminated at stage one.** Zero raw ERASES facts means R07's two
preconditions were never evaluated even once on this corpus — they cannot be
credited with, or blamed for, the zero result. This distinction is the whole
point of Phase 5 below.

---

## Phase 4 — Adjudication

**No final candidates exist to adjudicate.** Rather than stop there, the two
corpus sites that came closest to the pattern were opened and examined
directly, since "why did nothing match" is the actual research question:

The corpus contains exactly **2** calls from the closed erasing-coercion set
(both `<operator>.formatString`; zero `Number`/`String`/`Boolean`/`parseInt`/
`parseFloat`/unary-`+`/bitwise calls anywhere in 2,807 calls):

1. `lib/handlers/authorize-handler.js:256`, in `getState()`:
   `` throw new InvalidRequestError(`${message} parameter: \`state\``) ``
2. `lib/handlers/authorize-handler.js:408`, in `getCodeChallengeMethod()`:
   `` throw new InvalidRequestError(`Invalid request: transform algorithm '${algorithm}' not supported`) ``

Both are **error-message construction**: the coerced value flows into a
thrown exception's message string. Neither result is ever assigned to a local
that a subsequent guard then checks — there is no guard subject, so
`failure_state_facts.py` correctly produced no fact. This is a **correct
structural non-match, not a rejection**, and not a missed detection.

---

## Phase 5 — Specifically measuring R07

> Did the two R07 preconditions improve precision without simply suppressing
> everything?

**On this corpus, R07 neither improved nor suppressed anything, because it
never ran.** Zero raw ERASES facts reached it. Any claim that R07 "worked" or
"was too strict" here would be unsupported by the data.

Resolving the three-way question the brief specifies:

### → **A. The corpus contains no relevant success|failure-return + coercion patterns.**

This is established positively, not by assumption:

1. **The failure idiom is exceptions, not return-unions.** The corpus
   contains **157 `throw new …Error(…)` statements and zero functions that
   return an error value** (`grep` for `return new …Error` / error-valued
   returns: 0 matches). JS-STATE models `SUCCESS_VALUE | ERROR_VALUE`
   *returns*; this codebase represents failure by throwing. The modeled bug
   shape is structurally absent from this corpus by design choice, not
   hidden by tooling.
2. **Erasing coercions are nearly absent.** 2 of 2,807 calls, both in error-
   message construction (Phase 4).

### Ruling out B and C explicitly

**Not B ("patterns exist but R07 rejects them"):** R07 was never invoked —
0 facts reached it. Furthermore, R07's preconditions are demonstrably
**non-vacuous on this corpus**, which is the strongest available evidence
against overfitting:

| R07 precondition ingredient | Present in corpus? |
|---|---|
| `<operator>.instanceOf` guards | 5 |
| `<operator>.equals` guards | 6 |
| `<operator>.notEquals` guards | 7 |
| **Signal A closed-set guards, total** | **18** |
| Type hints containing a union | 43 |
| Unions with a failure-capable branch (Error/Null/Undefined/…) | **11** |

Both signals have real material to work with here. Had a genuine
erasure-before-guard pattern existed, R07 had the guard operators and the
union type evidence available to establish it. It found nothing because
stage one found nothing.

**Not C ("frontend/type evidence insufficient"):** Phase 2 is clean —
38/38 files, zero omissions, 78% REF coverage, 1,358 type hints on a
pure-JavaScript corpus. Type evidence is *thinner* than FxA's (expected: no
`.ts` files), but 11 failure-capable union hints were still recovered by
Joern's JS type recovery, so it is not absent.

---

## Phase 6 — Cross-corpus comparison

| | FxA (`mozilla/fxa`) | node-oauth2-server |
|---|---|---|
| Files scanned | 113 of 198 (85 silently dropped) | **38 of 38 (0 dropped)** |
| LOC | 77,966 | 3,859 |
| Language mix | 126 TS / 72 JS | **0 TS / 38 JS** |
| Calls | 50,638 | 2,807 |
| Raw erasures | 1 | **0** |
| R07 contracts established | 0 | 0 (never evaluated) |
| R07 guards established | 0 | 0 (never evaluated) |
| Final candidates | 0 | 0 |
| False positives | 1 (pre-R07) → 0 (post-R07) | 0 |
| True candidates | 0 | 0 |
| Dominant residual | RETURN_CONTRACT | **BASE-RATE / IDIOM MISMATCH** |

### Is R07 a general semantic precondition, or overfit to FxA?

**The honest answer: this corpus cannot settle that question, and it would be
wrong to claim it does.**

What can be said:

- **Evidence against R07 being vacuously narrow:** its ingredients occur
  naturally in an unrelated codebase (18 closed-set guard operators, 11
  failure-capable union hints). A precondition overfit to the FxA fixture
  would be expected to reference structures that essentially never appear
  elsewhere; these do appear.
- **Evidence R07 has *not* been positively validated:** it has still never
  fired on real code, in either corpus. Its only demonstrated true-positive
  behavior remains on the synthetic fixture. Two corpora at zero is **not**
  two confirmations — the second corpus never exercised it at all.
- **The dominant residual has shifted.** In FxA it was RETURN_CONTRACT (a
  precision problem). Here it is **base rate**: JS-STATE targets a
  return-union failure idiom, and this corpus uses exceptions exclusively.
  That is a *recall/applicability* problem, and it is the more important
  finding of this milestone.

---

## Next milestone (nominated only — not implemented)

Per the brief's own guidance for exactly this outcome: **do not tighten R07
further.** Two silent corpora mean we lack positive examples, not that we
need more filtering.

**Nominated: JS-STATE-R08 — Positive-Example Corpus Construction / Recall
Baseline.** Before any further precision work, obtain a corpus that
*provably contains* the modeled pattern, by one or both of:

1. **Historical vulnerability replay** — identify real, disclosed JS/TS CVEs
   of the failure-state-erasure class (e.g. authentication bypasses where an
   error sentinel was coerced before a check) and reconstruct them at the
   vulnerable commit.
2. **Idiom-targeted corpus selection** — deliberately select JS/TS projects
   that use `Result`-style / `[err, value]` / error-returning idioms
   (rather than `throw`), where the modeled shape is *possible* by
   construction. Node.js callback-style (`(err, result)`) and
   `neverthrow`/`fp-ts`-style codebases are the obvious candidates.

Without this, recall is unmeasured and unmeasurable, and no amount of
additional precision work can be evaluated.

**A secondary, separable question also surfaced** (recorded, not nominated):
JS-STATE currently models failure only as a *returned* value. This corpus
demonstrates that a large, security-relevant class of real JS/TS code
represents failure via `throw`/`catch` instead. Whether an analogous
erasure bug exists in the exception idiom (e.g. a caught error coerced
before an `instanceof` check in a `catch` block) is a genuinely different
bug shape and would be its own characterization milestone — not an
extension of R07.

---

# JS-REAL-R02 VERDICT

```text
CORPUS: node-oauth/node-oauth2-server @ 42367327a6a832afebf56e0ac6980f0c3e7e4b17
        lib/** + index.js — 38 JS files, 0 TS impl files, 3,859 LOC.
        Independent org, project, and framework from corpus 1 (mozilla/fxa).
        No Mozilla-specific profile or assumption reused.

FRONTEND HEALTH: GOOD. 38/38 files exported, ZERO silent omissions
        (bidirectional filesystem-vs-exported diff run explicitly to prevent
        a recurrence of FxA's bundle.js-style drop — came back clean).
        2,807 calls, 177 internal methods, 78% identifier REF coverage,
        1,358 type hints, 365 control structures. No parse failures.

RAW ERASURES: 0  (chain terminated at stage one)

R07 BOTH-ESTABLISHED: 0 — and critically, R07 was NEVER EVALUATED, because
        no raw ERASES fact reached it. R07 can be neither credited nor
        blamed for this result.

FINAL CANDIDATES: 0
TRUE CANDIDATES: 0
FALSE POSITIVES: 0
UNKNOWN: 0

CROSS-CORPUS RESULT: Outcome **A** — the corpus contains no relevant
        success|failure-return + coercion patterns. Established positively:
        157 `throw new …Error` statements vs. ZERO error-returning
        functions (this project represents failure by throwing, not by
        returning a union), and only 2 of 2,807 calls use any closed-set
        erasing coercion — both merely building thrown error-message
        strings, with no guard subject. Explicitly NOT outcome B (R07 never
        ran) and NOT outcome C (frontend clean, type evidence present).

DOMINANT RESIDUAL: BASE RATE / IDIOM MISMATCH — a shift from FxA's
        RETURN_CONTRACT residual. The blocker is no longer precision; it is
        that JS-STATE models a return-union failure idiom which this
        (exception-based) corpus does not use at all.

NEXT MILESTONE: JS-STATE-R08 — Positive-Example Corpus Construction /
        Recall Baseline (nominated only, not implemented). Do NOT tighten
        R07 further. Two silent corpora indicate missing positive examples,
        not excess permissiveness.
```

## Discipline note

R07's ingredients being non-vacuous here (18 closed-set guards, 11
failure-capable union hints) is genuine evidence against overfitting — but
it is **not** validation. R07 has still never fired on real-world code in
either corpus. Per the standing principle: *a quiet scanner is not
automatically a precise scanner*, and two quiet corpora are not two
confirmations. Recall remains entirely unmeasured, which is precisely what
the nominated next milestone exists to fix.
