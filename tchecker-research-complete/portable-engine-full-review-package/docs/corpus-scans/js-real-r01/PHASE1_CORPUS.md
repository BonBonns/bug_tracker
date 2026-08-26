# JS-REAL-R01 — Phase 1: Corpus

## Repository / commit

- Repository: https://github.com/mozilla/fxa (Monorepo for Mozilla Accounts, formerly Firefox Accounts)
- Cloned: shallow clone (`git clone --depth 1`), so only the tip commit is available locally.
- Commit: `e856cffdbf261c0b73ff51cde86045f77d26044b`
- Commit date: 2026-08-20 15:40:45 -0700
- Selection rationale: chosen because it is a real, actively-maintained,
  primarily-TypeScript authentication/session/identity codebase -- the exact
  domain the JS-STATE bug shape targets (failure-state erasure reaching an
  auth-sensitive sink). This is a deliberate choice, not a random sample, and
  is disclosed as such.

## Package / directories included

Scoped to `packages/fxa-auth-server/lib/{routes,tokens,crypto,oauth}` --
the actual authentication-decision-making code (HTTP route handlers, session
token issuance/verification, cryptographic primitives, OAuth flow) within the
FxA auth server package.

This is a deliberate narrowing, not a silent one:

- `packages/fxa-auth-server/lib/` in full is 463 files / ~150,109 LOC (ts+js).
  Running the complete monorepo (multiple packages, apps/, libs/) was out of
  scope for one measurement pass; `lib/{routes,tokens,crypto,oauth}` was
  selected as the highest-relevance subset for the JS-STATE bug shape
  specifically, at 198 files / 77,966 LOC.
- Everything else in the monorepo (all other `packages/*`, `apps/`, `libs/`,
  and `fxa-auth-server`'s own `lib/{email,senders,l10n,metrics,payments,
  profile,pushbox,inactive-accounts}`, `test/`, `scripts/`, `docs/`,
  `config/`, `bin/`) is EXCLUDED from this pass.
- `lib/senders` and `lib/email` (mailer/templating code, ~15K LOC) were
  considered and excluded: they are not where auth-decision guards/sinks live
  for this bug shape, and including them would dilute rather than sharpen the
  measurement.
- `test/` (89 files) and `scripts/` (97 files) were excluded because this
  pass targets production request-handling code; test fixtures and one-off
  operational scripts are a different measurement question.

## File counts (included corpus only)

| | count |
|---|---|
| `.ts`/`.tsx` files | 126 |
| `.js`/`.jsx` files | 72 |
| Total files | 198 |
| Total LOC (naive line count, ts+js combined) | 77,966 |

Per-subdirectory breakdown (from the source `lib/`, before staging):

| dir | .ts/.tsx | .js/.jsx | LOC |
|---|---|---|---|
| routes | 91 | 40 | 68,900 |
| tokens | 5 | 8 | 1,338 |
| crypto | 6 | 6 | 637 |
| oauth | 24 | 18 | 7,091 |

`routes` dominates by a wide margin -- most of the corpus's real signal will
come from there.

## Tool/engine versions

- jssrc2cpg / Joern CLI: `4.0.607` (from `io.joern.jssrc2cpg-4.0.607.jar`),
  installed from the official `joernio/joern` GitHub release, CPG schema
  `codepropertygraph-domain-classes 1.7.70`. Same install already verified in
  JSTS-R01/Gate 24/24-TS/JS-STATE-R02..R05.
- Normalizer / engine scripts (SHA-256, since this checkout of
  `portable-engine-full-review-package` is not a git repository and has no
  commit hash):
  - `export_ts_facts.sc`: `9411e4c7...b02c996f`
  - `normalize_ts_facts.py`: `a5eaf480...db15b6aa`
  - `failure_state_facts.py`: `e5803174...f218e5e`
  - `security_sensitive_reachability.py`: `22a4f7ef...9491c0a00df771`
  - `security_sink_profile.py`: `7b760ed9...9b28e79fd958a8`
  - `ProgramGraphLoader.java`: `c653e659...b63612e0cca`

## Known limitation carried into this scan (per instructions, not hidden)

R04/R05's path/use association is a **line-number and AST-branch-membership
approximation**, not a full CFG + reaching-definitions analysis. This scan
does not add new heuristics to compensate -- any imprecision this causes on
real code is exactly what Phase 5 is measuring, not something to paper over
mid-scan.
