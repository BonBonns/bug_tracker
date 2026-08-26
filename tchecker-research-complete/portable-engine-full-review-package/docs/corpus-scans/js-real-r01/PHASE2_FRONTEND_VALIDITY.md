# JS-REAL-R01 — Phase 2: Frontend Validity

Real `jssrc2cpg` run against the staged corpus (`corpus_src/`, 198 files,
77,966 LOC). Elapsed: CPG generation 25s, fact export 51s (`ReachingDefPass`
alone took 15.2s of that, over 1244 methods).

## Files attempted / parsed / failures

| | count |
|---|---|
| Files staged as input | 198 |
| Files with >=1 representation in `methods.tsv` (incl. the implicit per-file top-level method) | 113 |
| Files with ZERO representation anywhere in exported facts | 85 |

**This is a real, material gap — 43% of the staged corpus produced no facts
at all — and it is disclosed here per instructions, not treated as "0 findings
because nothing to find."**

Breaking down the 85 missing files:

- **84 files**: all `*.spec.ts` / `*.spec.js` (test files co-located with
  production source inside `routes/`, `tokens/`, `crypto/`, `oauth/` — these
  were NOT in the `test/` directory I excluded in Phase 1, they are
  interspersed alongside the production code they test). This matches a
  **known, previously-documented jssrc2cpg behavior**: JSTS-R05's `run.sh`
  already has a comment recording "jssrc2cpg SILENTLY IGNORES sources whose
  names match test patterns (MEASURED: e2e.ts ignored, app.ts accepted —
  AstGenRunner default ignores)." This scan reproduces that same behavior at
  much larger scale and confirms it is systematic (every single `.spec.*`
  file was dropped, zero exceptions), not occasional.
- **1 file**: `tokens/bundle.js` — genuinely anomalous, does NOT match the
  test-file pattern. Investigated directly:
  - Confirmed present and byte-identical to the source repo (no staging
    corruption).
  - Confirmed it is the only file with that name anywhere in the corpus (no
    collision with another `bundle.js`).
  - Confirmed zero references anywhere in `methods.tsv`, `type_decls.tsv`, or
    `literals.tsv` — not "parsed but empty," genuinely absent.
  - `jssrc2cpg.sh` produced **zero stdout/stderr output for the entire run**
    (`gen.log` is 0 bytes) — there is no diagnostic channel in the default CLI
    invocation that would explain this drop. `--help` offers no verbosity
    flag.
  - Best-supported explanation, not confirmed with certainty: `bundle.js` is
    a very common conventional filename for webpack/rollup build output, and
    static-analysis frontends commonly default-ignore such filenames to avoid
    choking on generated code. This particular `bundle.js` is NOT build
    output — it's a small, hand-written HKDF/HMAC token-encryption module
    (`bundle`/`unbundle` functions) — so if this hypothesis is correct, it
    would mean **a real, security-relevant, hand-written source file is being
    silently dropped because of a filename convention collision**, with zero
    warning.

This second finding is reported with appropriate uncertainty about mechanism,
but high confidence about the *fact pattern* (real file, unique name, valid
syntax, silently absent, zero diagnostics) — flagging it rather than
resolving it, per the instruction not to add heuristics or go beyond
measurement during this pass.

## Facts exported (from the 113 files the frontend did represent)

| Fact file | Rows |
|---|---|
| `methods.tsv` | 2,926 (1,187 internal/in-corpus, 1,739 external/stub — builtins, npm deps, etc.) |
| `calls.tsv` | 50,638 |
| `arguments.tsv` | 98,645 |
| `identifiers.tsv` | 104,976 total; **76,897 (73%) carry >=1 REF edge** to a LOCAL/PARAMETER |
| `locals.tsv` | 14,595 |
| `parameters.tsv` | 8,372 |
| `control_structures.tsv` | 2,098 |
| `condition_identifiers.tsv` | 2,203 (REF-resolved identifiers inside guard conditions) |
| `guard_then_branch_members.tsv` | 44,696 (nodes inside some guard's then-branch) |
| `call_argument_identifiers.tsv` | 117,641 (REF-resolved identifiers inside call arguments, full-subtree) |
| `closure_bindings.tsv` / `local_closure.tsv` | 2,962 / 2,962 |
| `type_decls.tsv` | 1,599 |
| `members.tsv` | 957 |
| `returns.tsv` | 2,997 |
| `literals.tsv` | 5,699 |
| `type_hints.tsv` | 10,312 |
| `method_refs.tsv` | 816 |

## Higher-level fact derivations (existing normalizers, run unchanged)

- **Closure/capture facts** (`capture_facts.py`): **2,962 captures** derived.
- **Property/keyed-state facts** (`state_facts.py`): **15,505 state reads**,
  **6,398 state writes** derived (keyed index-access reads/writes,
  `recv[key]` / `recv[key] = val` patterns — this is the only
  property/object-flow fact family this pipeline currently has; there is no
  separate general dot-property (`recv.prop`) dataflow fact family beyond
  `members.tsv`'s static declared-member list and raw
  `<operator>.fieldAccess` calls, which is a real, disclosed narrowness of
  "property/object facts" for this pipeline, not a corpus artifact).

## CFG facts available: NONE (exported)

Joern computes a CFG internally — visible in `gen.log`'s
`CfgCreationPass`/`ReachingDefPass` log lines during CPG construction — but
**`export_ts_facts.sc` does not export any CFG edge as a fact**, and never
has. This is the exact, direct manifestation of the "known limitation" flagged
before this scan started: R04/R05's branch/reassignment exclusions are
AST-branch-membership and line-number approximations specifically *because*
no CFG fact exists to consume instead. This scan does not add a CFG export
now — that would be an engine change, out of scope for a measurement pass —
but the absence is now measured and stated plainly rather than left as an
abstract caveat.

## Verdict on frontend completeness

The frontend output is **materially incomplete for the specific goal of
scanning test-adjacent security logic**, but not incomplete in a way that
invalidates Phase 3 measurement of production route/token/crypto/oauth code:

- The 84 `.spec.*` exclusions are irrelevant to this scan's purpose (JS-STATE
  targets production guard/sink logic, not test assertions) and are the
  **expected, previously-documented** behavior, not a new problem.
- The `bundle.js` exclusion IS a genuine, unexplained gap in a
  security-relevant file (HMAC-based token bundling). Per instructions, this
  is characterized here rather than silently worked around; Phase 3/4 results
  below **do not include any analysis of `tokens/bundle.js`**, and that
  absence should be read as "not scanned," not "scanned and clean."

Proceeding to Phase 3 on the 113 successfully-parsed production files, with
the above gap stated up front rather than discovered later.
