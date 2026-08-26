# JS-PROV-R06 — Frontend Type-Binding Correctness Audit

**Characterization + disposition only.** No propagation implemented, no
Fable-side type-name repair, no silent normalization or override. R07 unchanged.

Permanent distinction adopted from R05:

```text
ANY                  = weak evidence          -> safe to abstain on
WRONG CONCRETE TYPE  = actively dangerous     -> can fabricate relationships
```

Only the second can manufacture provenance that never existed.

---

## Part A/B — Real-corpus prevalence

Four existing corpora searched for collision-prone declarations; **no new
corpora selected.**

| Corpus | Same-short-name decls across files |
|---|---|
| `mozilla/fxa` (routes/tokens/crypto/oauth) | **4**: `Customs`(×3), `DB`(×2), `OtpRedisAdapter`(×2), `ScopeSetLike`(×2) |
| `node-oauth/node-oauth2-server` | 0 |
| `gobeam/truthy` (NestJS) | 0 |
| `paralect/koa-api-starter` (Koa) | 0 |

Collisions are real and cross-file in fxa, e.g. `Customs`/`DB` declared
independently in `routes/mfa.ts`, `routes/passkeys.ts`, `routes/recovery-phone.ts`.

### What the frontend actually bound

```text
TYPE_DECLs present and correctly distinct, e.g.
  Customs  id=167503725206  routes/mfa.ts::program:Customs            ext=false
  Customs  id=167503725317  routes/passkeys.ts::program:Customs       ext=false
  Customs  id=167503725447  routes/recovery-phone.ts::program:Customs ext=false
  Customs  id=167503725918  Customs                                   ext=true  <-- stub

Bindings observed:
  PARAM this      -> routes/mfa.ts::program:Customs        (file-matched)  CORRECT
  PARAM this      -> routes/passkeys.ts::program:DB        (file-matched)  CORRECT
  PARAM customs   -> Customs        (bare external stub)                  AMBIGUOUS
  PARAM db        -> DB             (bare external stub)                  AMBIGUOUS
  PARAM db        -> ../db:DB       (module-qualified import path)        CORRECT
```

**Key result: no concrete-wrong binding was found in the real corpora.**

- `this` parameters bind **correctly** in every case — resolved lexically from
  the enclosing declaration, never by name lookup.
- Non-`this` parameters whose annotation is a collision name bind to the
  **bare external stub** (`Customs`, `DB`), i.e. they degrade to
  AMBIGUOUS/unresolved rather than picking a wrong module-qualified decl.

**Why R05-2 did not reproduce here:** the R05 defect requires
*import-alias + same-named local declaration in the importing file*. The fxa
collisions are independently-declared local interfaces that are never imported
into one another's files, so the collision never has to be resolved. The
pattern is collision-*prone* but not collision-*exercised*.

That is a genuinely different result from what R05 predicted, and it must not
be overstated in either direction: R05-2 is a **real, reproducible frontend
defect** (verified on a minimal fixture), but it is **not shown to be endemic**
in these four corpora.

### Error-class quantification (fxa, the only corpus with collisions)

```text
identifiers inspected                       47,107
  ANY / unresolved                          19,286   (41%)
  malformed typeFullName                         0
  concrete WRONG (verified)                      0
parameters                                   8,372
  ANY / unresolved                           6,506   (78%)
  malformed typeFullName                         0
malformed names in dynamicTypeHintFullName      15   e.g. routes/utils/otp:ts::program:OtpUtils
alias-induced misbindings                        0   (pattern not exercised)
interface/structural conflations                 0   (see Part C)
```

Separating the two failure modes as required:

```text
FALSE_NEGATIVE (missing type):   very high — 41% of identifiers, 78% of params
FALSE_POSITIVE (wrong concrete): ZERO observed in real corpora
```

The malformed-separator defect **is** present in real code (15 hint
occurrences, `routes/utils/otp:ts::program:OtpUtils` — colon where a dot
belongs), but only in `dynamicTypeHintFullName`, never in `typeFullName`. That
localizes it: it is a hint-construction bug, and hints were already ruled
unreliable in R05 (aggregated per identifier, not per site).

---

## Part C — R01 framework discriminator, re-tested against a DECLARED interface

R05 weakened this claim, so it was rebuilt with the harder control R01 never
had (R01 used only an inline object-literal type):

```text
post mfn=express:express:<returnValue>:post   recv=app:express:express:<returnValue>
post mfn=<unknownFullName>                    recv=notFramework:ANY
post mfn=<unknownFullName>                    recv=nf2:disc.ts::program:FakeRouter
```

**The discriminator survives — and for a stronger reason than R01 originally
claimed.**

R01 described the discriminator as "module-derived type vs object-literal
type." That framing *was* partly relying on recovered type shape, which R05
correctly flagged as fragile. The measurement here shows the real
discriminator is different and more robust:

> The registration call's **`methodFullName`** resolves to
> `express:express:<returnValue>:post` **only** when the receiver's type traces
> to the framework import. For both lookalikes — the declared-interface
> variable and the class implementing that interface — `methodFullName` is
> `<unknownFullName>`.

Notably `nf2` **does** carry a confident concrete type
(`disc.ts::program:FakeRouter`) and still fails to produce a framework
`methodFullName`. So the discriminator is not defeated by a lookalike having a
good type; it depends on the *module provenance* of the receiver, which is
independent evidence.

**R01 claim disposition: UPHELD, with its stated basis corrected.** The
conclusion stands; the *reason* given in R01 was imprecise and is amended here.
This is a retroactive correction of reasoning, not of result.

## Part D — Structural identity routes

| Route | Exact module/decl identity? | Survives aliases? | Survives stubs? | Avoids short-name matching? |
|---|---|---|---|---|
| `TYPE` → `referencedTypeDecl` | YES when it resolves | **NO** (R05-2) | **NO** — resolves to the `ext=true` stub for bare names | YES |
| `typeFullName` string | partial (module-qualified forms only) | NO | NO | NO |
| import binding → declaration | not exposed as an edge in this export | — | — | — |
| constructor call → resolved METHOD | promising, untested at scale | unknown | n/a | YES |
| `methodFullName` on a call | **YES for framework provenance** (Part C) | n/a | n/a | YES |

Measured directly:

```text
app          type=express:express:<returnValue>   -> TYPE_DECL[]              (none — but mfn works)
notFramework type=ANY                             -> TYPE_DECL[…:ANY:ext=true]
nf2          type=disc.ts::program:FakeRouter     -> TYPE_DECL[…:FakeRouter:ext=false]
```

**No general-purpose safe structural identity route exists** for arbitrary
values: `referencedTypeDecl` fails on aliases and resolves bare names to
external stubs, and there is no exposed import-binding edge. However, a
**specific** safe route exists for the one thing JS-PROV actually needs —
framework provenance via `methodFullName` on the registration call — and it
does not go through `typeFullName` at all.

## Part E — Version sensitivity

```text
Joern / jssrc2cpg:            4.0.607
codepropertygraph-domain-classes: 1.7.70
```

**Not tested against a newer release.** Doing so would require downloading and
installing a second ~1.7GB Joern distribution and re-running the fixtures — not
"cheap and controlled" as the milestone conditioned, and the instruction was
explicit not to upgrade the project mid-milestone. Version sensitivity is
therefore **UNDETERMINED**, and the upstream report below is written against
the pinned version only.

## Part F — Disposition

```text
DISPOSITION: VERSION_PIN_SUFFICIENT  (with an upstream report filed for the record)
```

Reasoning, in the order the evidence supports:

- **Not `UPSTREAM_BLOCKER`.** The defect is real but was **not exercised** by
  any of the four real corpora. Nothing currently in scope is blocked by it.
- **Not `NOT_REPRODUCIBLE`.** It reproduces deterministically on the R05-2
  fixture at the pinned version.
- **Not `FABLE_CAN_CONTAIN`.** Containment would require independently
  detecting a wrong binding, and the only available detector — comparing the
  bound decl against other decls of the same short name — is *the same broken
  short-name logic*. A name-based repair is explicitly disallowed, and no
  non-name-based structural check is available (Part D).
- **`VERSION_PIN_SUFFICIENT`** is what the evidence supports: the behaviour is
  deterministic at a pinned version, the pattern is absent from current
  corpora, and the correct long-term action is upstream. The pin must be
  recorded so that a Joern upgrade re-triggers this audit.

### Minimal upstream report (prepared, not filed)

```text
COMPONENT:  jssrc2cpg (Joern 4.0.607, codepropertygraph-domain-classes 1.7.70)
TITLE:      Imported class alias mis-binds to a same-named local class

FIXTURE:
  // mod/other.ts
  export class Router { m = 1 }
  // main.ts
  import { Router as R } from './mod/other';
  class Router { r = 1 }
  const foreign = new R();

EXPECTED:   foreign.typeFullName == "mod/other.ts::program:Router"
ACTUAL:     foreign.typeFullName == "main.ts::program:Router"

CPG STATE:  both TYPE_DECLs exist and are correct:
              id=…555  main.ts::program:Router       file=main.ts
              id=…570  mod/other.ts::program:Router  file=mod/other.ts
            The declarations are right; the identifier->type binding selects
            the wrong one.

WHY WRONG:  `R` is bound by an import to mod/other's declaration. Resolving it
            to the lexically-local `Router` ignores the import binding and
            appears to match on short name.

IMPACT:     Downstream analyses consuming typeFullName receive a confident but
            incorrect nominal type. Stated as an incorrect frontend type
            binding with downstream analysis consequences — no security-impact
            claim is made.

SECONDARY:  malformed full names observed in dynamicTypeHintFullName, e.g.
            "routes/utils/otp:ts::program:OtpUtils" (':ts::' where '.ts::' is
            expected). 15 occurrences in a 78k-LOC real corpus.
```

## Fable safety rule (in force until disposition changes)

> A concrete frontend type must not automatically be treated as trusted
> semantic identity where short-name collisions or structural-interface
> substitution are possible. Prefer abstention over propagating a possibly
> fabricated type.

---

# JS-PROV-R06 VERDICT

```text
CORPORA CHECKED:                  4 (fxa, node-oauth2-server, truthy,
                                  koa-api-starter). No new corpora selected.
COLLISION SITES:                  4 name-groups, fxa only (Customs x3, DB x2,
                                  OtpRedisAdapter x2, ScopeSetLike x2);
                                  0 in the other three corpora.
CONCRETE WRONG TYPES:             0 in real corpora. `this` binds correctly
                                  (lexical); collision-name params degrade to
                                  bare EXTERNAL STUBS (ambiguous), which is the
                                  SAFE failure mode. R05-2 requires
                                  import-alias + same-named local in one file —
                                  a pattern present in none of the four.
ANY/UNRESOLVED:                   41% of identifiers (19,286/47,107);
                                  78% of parameters (6,506/8,372).
MALFORMED TYPES:                  0 in typeFullName; 15 occurrences in
                                  dynamicTypeHintFullName (real code) —
                                  localizes it to hint construction.
STRUCTURAL-INTERFACE CONFLATIONS: 0 that defeat the discriminator (Part C).

R01 FRAMEWORK DISCRIMINATOR STILL VALID:  YES — but its STATED BASIS is
                                  CORRECTED. It does not rest on
                                  "module-derived vs object-literal type shape"
                                  (fragile, as R05 warned). It rests on the
                                  registration call's `methodFullName`
                                  resolving to `express:...:post` only when the
                                  receiver traces to the framework import. A
                                  class with a confident concrete type
                                  (FakeRouter) implementing a declared
                                  interface still yields `<unknownFullName>`.

SAFE STRUCTURAL TYPE IDENTITY AVAILABLE:  NO in general (referencedTypeDecl
                                  fails on aliases and resolves bare names to
                                  external stubs; no import-binding edge is
                                  exposed). YES for the specific case
                                  JS-PROV needs: framework provenance via
                                  `methodFullName`, which bypasses
                                  typeFullName entirely.

UPSTREAM BUG REPRODUCED:          YES (deterministic on the R05-2 fixture at
                                  the pinned version); NOT exercised by any of
                                  the four real corpora.
VERSION SENSITIVITY:              UNDETERMINED — not tested against a newer
                                  release; a second ~1.7GB Joern install was
                                  outside the "cheap and controlled" condition,
                                  and upgrading mid-milestone was disallowed.
DISPOSITION:                      VERSION_PIN_SUFFICIENT, with a minimal
                                  upstream report prepared (above). NOT
                                  FABLE_CAN_CONTAIN: containment would require
                                  the same broken short-name logic, and no
                                  non-name-based structural check exists.

PROPAGATION PROMOTION:            NO. Unchanged. R04's rule is well-specified
                                  but its inputs are 78%-ANY on real
                                  parameters, and the wrong-binding defect,
                                  while not endemic, is uncontainable in Fable.
PROVENANCE PROMOTION:             NO — but for a DIFFERENT and weaker reason
                                  than before. JS-PROV-R01's discriminator is
                                  now shown to NOT depend on the unreliable
                                  type-recovery path, so it is not disqualified
                                  by R05/R06. It remains blocked by
                                  JS-PROV-R02's Gate 1 (only one of two
                                  mechanisms survived real code) — a coverage
                                  problem, not a correctness one.

DOMINANT GAP:                     Type EVIDENCE SPARSITY, not incorrectness.
                                  The audit inverted the expected finding:
                                  wrong concrete types are rare-to-absent in
                                  real code, while 78% of real parameters carry
                                  no type at all. Propagation was proposed to
                                  fill that sparsity — but propagating from a
                                  78%-ANY base yields little, and R04 already
                                  showed ANY must not reduce to a concrete type.

NEXT MILESTONE:                   JS-PROV-R07 — Registration-Provenance
                                  Cross-Module Recovery (characterization).
                                  Rationale: Part C/D established that
                                  `methodFullName` carries framework provenance
                                  WITHOUT going through typeFullName. Since
                                  JS-PROV-R02's Koa failure was a lost receiver
                                  TYPE, characterize whether the Koa
                                  registration sites can instead be recovered
                                  via callee/methodFullName evidence — closing
                                  Gate 1 without needing type propagation or
                                  the defective type path at all.
```

## Discipline note

R06 was designed expecting to confirm that wrong bindings are endemic and to
disqualify earlier results. It did the opposite on both counts, and both
reversals are recorded rather than smoothed over:

- **Wrong concrete types: 0 in real corpora.** The R05 defect is real and
  reproducible but requires a pattern none of the four corpora contain. The
  honest statement is "real defect, not shown endemic," not "type recovery is
  broken."
- **R01's discriminator was upheld, but its stated reason was wrong.** R05
  suspected it leaned on recovered type shape; Part C shows it actually rests
  on `methodFullName`, independent of `typeFullName`. The *result* survives;
  the *reasoning published in R01* is corrected here.

The genuinely new finding is that the problem has inverted: the audit went
looking for false precision and found overwhelming **absence** instead — 78% of
real parameters are `ANY`. That reframes what propagation could ever be worth
and directly motivates R07's different approach.
