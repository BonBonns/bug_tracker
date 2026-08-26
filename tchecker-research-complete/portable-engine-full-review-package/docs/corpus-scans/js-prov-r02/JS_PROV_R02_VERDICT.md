# JS-PROV-R02 — Real-Code Provenance Validation

**Validation only.** `ExternalInputOriginFact` NOT promoted. No engine changes;
no framework-specific patches applied during the scan; no name heuristics added.

---

## Phase 1 — Corpus record

```text
CORPUS A
  REPOSITORY: github.com/gobeam/truthy  (NestJS headless CMS API:
              auth, user/role/permission management, OTP, RBAC)
  COMMIT:     9b9a61be6c0a6439c2afeb4170ef42b545e8fe54  (2025-02-01)
  FRAMEWORK:  NestJS  (ANNOTATION mechanism)
  TS FILES:   131      JS FILES: 0      LOC: 6,410
  INCLUDED:   src/**   EXCLUDED: none (0 .spec.ts present in src)

CORPUS B
  REPOSITORY: github.com/paralect/koa-api-starter  (Koa REST API:
              signup/signin/forgot-password/reset-password, token auth)
  COMMIT:     19b1a2657854be79f8eb10904e7ba28013643d2a  (2022-04-18)
  FRAMEWORK:  Koa + @koa/router  (REGISTRATION mechanism)
  JS FILES:   58       TS FILES: 0      LOC: 1,613
  INCLUDED:   src/**   EXCLUDED: none

FRONTEND VERSION: jssrc2cpg 4.0.607, codepropertygraph-domain-classes 1.7.70
NORMALIZER HASH:  export_ts_facts.sc 9411e4c7…b02c996f
CORE HASH:        js_state_r07.py b18bc7aa…6d4d309 (UNCHANGED)
JS-PROV-R01 CODE STATE: unchanged; R01 produced no code, only characterization
```

Independent organizations, independent frameworks, independent provenance
mechanisms. Corpus B is a "starter" rather than a large product — disclosed as
a limitation; it is real application code with genuine auth flows, but it is
small (1.6k LOC).

## Phase 2 — Frontend validity

| | Corpus A | Corpus B |
|---|---|---|
| Files attempted (filesystem) | 131 | 58 |
| Files exported | **131** | **58** |
| **Silent omissions** | **0** | **0** |
| Parse failures | 0 | 0 |
| Methods | 1,260 | 428 |
| Calls | 12,556 | 2,900 |
| Parameters | 3,286 | 1,032 |

Bidirectional filesystem-vs-export diff run on both (the check that caught
FxA's `bundle.js`). Clean in both directions. **Frontend health: GOOD.**

## Phase 3 — Ground truth (enumerated from source, not from the detector)

```text
CORPUS A: 7 @Controller classes; 39 route methods (@Get/@Post/@Put/@Delete/@Patch)
          param decorators: @Body=16  @Query=6  @Param=12  @Headers=0
CORPUS B: 14 router.<verb> registrations (5 get, 7 post, 1 put, 1 delete)
          ctx reads: ctx.request.body=1, ctx.query=1, ctx.params=0
```

## Phase 4 — R01 mechanisms run unchanged

### Corpus A — ANNOTATION provenance: exact match to ground truth

```text
CONTROLLER_CLASSES_RECOGNIZED = 7 / 7
REAL_HANDLERS      = 39
HANDLERS_RECOGNIZED = 33   (>=1 annotated parameter)
HANDLERS_PARTIAL    = 6    (zero parameters)
HANDLERS_UNKNOWN    = 0

BODY_ORIGINS   = 16   (ground truth 16)
QUERY_ORIGINS  =  6   (ground truth  6)
PATH_PARAM     = 12   (ground truth 12)
HEADER_ORIGINS =  0   (ground truth  0)
COOKIE_ORIGINS =  0   (ground truth  0)
```

Every origin-family count matches source ground truth **exactly**. All 39
route methods were located; the 6 "PARTIAL" are handlers that genuinely take
no parameters (`health`, `index`, `userStat`, `osStat`, `browserStat`,
`syncPermission`) — correct abstention, not a miss.

Discrimination quality: the corpus also uses non-HTTP decorators
(`@GetUser`, `@UploadedFile`, `@Req`, `@Res`). These were resolved and
displayed but **not** counted as HTTP origin families — the mechanism reports
the annotation it sees rather than assuming any decorator is an input origin.

### Corpus B — REGISTRATION provenance: handler identity yes, framework identity no

```text
REAL_HANDLERS       = 14
HANDLERS_RECOGNIZED =  0   (full chain incl. framework identity)
HANDLERS_PARTIAL    = 13   (handler identity resolved, framework identity lost)
HANDLERS_UNKNOWN    =  1
BODY/QUERY/PARAM/HEADER/COOKIE ORIGINS = 0 (chain never completes)
```

All 14 registrations were *located*, and handler identity resolves precisely:

```text
post ... args=0:ID(router:ANY) 1:LIT 2:CALL
         3:ID(validator:resources/account/sign-in/index.js::program:validator)
         4:ID(handler:resources/account/sign-in/index.js::program:handler)
```

Handlers, validators, and middleware chains all resolve to exact method
fullNames — position distinguishes them. **But `router` types as `ANY`**, so
module-derived framework identity is absent and the chain cannot complete.

Root cause, confirmed from source: the router is constructed in one module and
**passed across module boundaries as a function parameter**:

```js
// resources/account/public.js
const Router = require('@koa/router');
const router = new Router();
require('./sign-in').register(router);   // router crosses a module boundary
module.exports = router.routes();
```

This is exactly the alias/re-export boundary R01 identified in fixtures
(`const reexported = namedHandler` → `ANY`), now confirmed at scale on real
code. It is a cross-module parameter-type propagation failure, not a Koa
modelling gap.

**A second, distinct failure was observed and is worth recording:** on
`router.get(...)` calls, `methodFullName` resolved to
`ctx:cookies:<returnValue>:<member>(cookies):get` — Joern mis-resolved
`router.get` to Koa's `ctx.cookies.get`. This is a **type-recovery
mis-resolution producing a wrong framework identity**. It did not cause a
false origin here (the receiver is `ANY`, so the chain still abstains), but a
promoted implementation must not treat `methodFullName` as trustworthy without
also validating the receiver's type — otherwise this exact pattern could
fabricate a framework identity.

## Phase 5 — Manual adjudication

**Corpus A — 10 recognized handlers inspected against source:**

| Handler | Real handler | Param role | Origin family | Property path | FP |
|---|---|---|---|---|---|
| `AuthController.register` | YES | YES (idx1 `@Body`) | BODY | YES | NO |
| `AuthController.login` | YES | YES (idx3 `@Body`; idx1/2 `@Req`/`@Res` not claimed) | BODY | YES | NO |
| `AuthController.activateAccount` | YES | YES (idx1 `@Query`) | QUERY | YES | NO |
| `AuthController.forgotPassword` | YES | YES | BODY | YES | NO |
| `AuthController.resetPassword` | YES | YES | BODY | YES | NO |
| `AuthController.update` | YES | YES (idx1 `@Param`, idx2 `@Body`) | PATH_PARAM + BODY | YES | NO |
| `AuthController.findOne` | YES | YES | PATH_PARAM | YES | NO |
| `EmailTemplateController.update` | YES | YES | PATH_PARAM + BODY | YES | NO |
| `PermissionsController.findAll` | YES | YES (`@Query`) | QUERY | YES | NO |
| `RolesController.create` | YES | YES (`@Body`) | BODY | YES | NO |

**10/10 correct. 0 false positives.** Multi-annotation handlers
(`@Param` + `@Body`) were correctly decomposed into two distinct origins.

**Corpus A — the 6 non-recognized handlers:** all verified in source to take
**zero parameters**. Correct abstention; root cause N/A.

**Corpus B — 10 unrecognized/partial handlers, root causes:**

| Handler | Root cause |
|---|---|
| `sign-in/handler` | `TYPE_RECOVERY_FAILURE` (router param crosses module boundary → ANY) |
| `sign-up/handler` | `TYPE_RECOVERY_FAILURE` |
| `forgot-password/handler` | `TYPE_RECOVERY_FAILURE` |
| `reset-password/handler` | `TYPE_RECOVERY_FAILURE` |
| `resend-email/handler` | `TYPE_RECOVERY_FAILURE` |
| `verify-email/handler` | `TYPE_RECOVERY_FAILURE` + wrong-mfn mis-resolution |
| `verify-reset-token/handler` | same |
| `user/get-current/handler` | `TYPE_RECOVERY_FAILURE` |
| `user/list/handler` | `TYPE_RECOVERY_FAILURE` |
| `sign-out` inline handler | `TYPE_RECOVERY_FAILURE` + inline arrow types as a signature, not a method fullName |

Dominant miss cause is a **single** bounded mechanism:
`TYPE_RECOVERY_FAILURE` at cross-module parameter passing — 14/14.

A secondary, separate observation: most Corpus B handlers read
`ctx.validatedData.*` rather than `ctx.request.body` — a **middleware-derived
property** produced by a Joi validation middleware. Even with framework
identity intact, the origin path would need to traverse middleware-written
properties. Recorded as `PROPERTY_MODEL` / `CALL_BASED_ORIGIN`, not patched.

## Phase 6 — Negative principle re-tested on real code

```text
REAL_CODE_NEGATIVE_LOOKALIKES:
  Corpus A: non-HTTP decorators present (@GetUser, @UploadedFile, @Req, @Res)
            -> resolved but NOT claimed as HTTP input origins
            non-@Controller classes with methods -> not enumerated as handlers
  Corpus B: `.get(...)` on non-router receivers (ctx.cookies.get, Map-like
            accessors) present; `handler`/`validator` functions defined but
            reachable only via cross-module wiring
            -> all abstained

FALSE_ORIGINS: 0   (both corpora)
```

No origin was produced from names or shapes in either corpus. Corpus B
produced **zero** origins overall — it abstained completely rather than
guessing, which is the desired failure mode.

## Phase 7 — Mechanism-specific validation

```text
ANNOTATION_PROVENANCE (NestJS):  VALIDATED ON REAL CODE
  @Body / @Query / @Param remain visible and correctly bound to the exact
  method parameter index in production code. @Headers absent from this corpus
  (0 in ground truth) -> UNVALIDATED, not failed.

REGISTRATION_PROVENANCE (Koa):   NOT VALIDATED ON REAL CODE
  module identity -> registration call: BROKEN (router: ANY)
  registration -> exact callback:       WORKS (exact method fullNames)
  callback -> exact parameter position: WORKS
  Survives aliases within a module; does NOT survive cross-module parameter
  passing, which is the normal structure of this real application.
```

Express registration provenance *was* validated on real code in JS-STATE-R13
(tarkov `app.post('/auth', …)` full chain). So registration provenance is
validated for the same-module case and refuted for the cross-module case.

## Cross-corpus table

```text
                   CORPUS A (NestJS)        CORPUS B (Koa)
framework          NestJS / annotation      Koa+@koa/router / registration
real handlers      39                       14
recognized         33                       0
partial            6 (zero-param, correct)  13
unknown            0                        1
recognition rate   85% (100% of handlers    0%
                   that have parameters)
false origins      0                        0
body origins       16 (GT 16)               0
query origins      6  (GT 6)                0
path origins       12 (GT 12)               0
header origins     0  (GT 0)                0
cookie origins     0  (GT 0)                0
dominant miss      none (6 zero-param       TYPE_RECOVERY_FAILURE at
                   abstentions correct)     cross-module parameter passing
```

---

# JS-PROV-R02 VERDICT

```text
REAL-CODE MECHANISMS VALIDATED:
  REGISTRATION: PARTIAL — validated same-module (Express/tarkov, R13);
                REFUTED cross-module (Koa corpus, 0/14). The failure is a
                single bounded cause: framework-object type does not survive
                being passed as a parameter across module boundaries.
  ANNOTATION:   VALIDATED — 7/7 controllers, 39/39 route methods located,
                33/33 parameter-bearing handlers recognized, origin-family
                counts an EXACT match to source ground truth (16/6/12/0),
                10/10 manual adjudication correct.

PRECISION:            100% on both corpora. Zero false origins, zero
                      name-derived origins, zero shape-derived origins.
RECALL/ABSTENTION:    NestJS 85% (100% of parameter-bearing handlers).
                      Koa 0% — complete, clean abstention rather than guessing.
NEGATIVE CONTROLS:    HELD. Non-HTTP decorators, non-router `.get()`
                      receivers, and unregistered handler-shaped functions all
                      correctly produced nothing.

PROMOTION_JUSTIFIED: NO

  Gate 1 (>=2 independent mechanisms survive real code):  NOT MET
        Annotation survives. Registration does not survive THIS real corpus.
        Express/R13 is same-module only. One mechanism validated, not two.
  Gate 2 (recognized-handler precision high):             MET (100%)
  Gate 3 (zero false origins on real lookalikes):         MET (0)
  Gate 4 (unknown frameworks/handlers remain UNKNOWN):    MET
  Gate 5 (no identifier-name dependence):                 MET
  Gate 6 (origin families distinguishable):               MET (exact GT match)
  Gate 7 (failures bounded and characterized):            MET (single cause)

  Six of seven gates pass, and the one failure is bounded and diagnosed. But
  Gate 1 is the gate this milestone exists to test, and a shared provenance
  layer promoted on one validated mechanism would be exactly the
  "misleadingly general fact" R01 warned against.

  Honest current statement:
      NESTJS_ANNOTATION_PROVENANCE_SUPPORTED
      EXPRESS_SAME_MODULE_REGISTRATION_PROVENANCE_SUPPORTED
      GENERAL_REGISTRATION_PROVENANCE_NOT_YET_SUPPORTED

DOMINANT RESIDUAL: Cross-module framework-object type propagation.
                   `const router = new Router()` in module X, then
                   `register(router)` into module Y, collapses the receiver to
                   ANY and severs framework identity. This single cause
                   accounts for 14/14 Koa misses and matches the alias/
                   re-export boundary R01 predicted from fixtures.
                   Secondary: middleware-derived properties
                   (`ctx.validatedData.*`) mean the origin path would need to
                   traverse middleware writes even with identity intact.
                   Tertiary: `methodFullName` mis-resolution
                   (`router.get` -> `ctx:cookies:...:get`) means mfn must not
                   be trusted without receiver-type corroboration.

NEXT MILESTONE: JS-PROV-R03 — Cross-Module Framework-Identity Propagation
                Characterization. Characterization only. Determine whether
                framework-object identity can be propagated across module
                boundaries from existing facts (import graph, exports,
                argument-to-parameter binding at the `register(router)` call
                site) or whether this is a FRONTEND_GAP requiring
                interprocedural type propagation jssrc2cpg does not perform.
                Acceptance anchor already exists: Corpus B's 14 registrations
                must gain framework identity WITHOUT any name heuristic, and
                Corpus A must remain unchanged. Only after that should
                ExternalInputOriginFact promotion be reconsidered.
```

## Architectural note preserved

R01's discovery holds up under production validation and should be preserved
explicitly in the architecture: **there is no single universal "web handler"
proof mechanism.** Annotation provenance and registration provenance are
independent evidence routes with *different* failure modes — annotation
provenance was completely unaffected by the cross-module structure that
destroyed registration provenance, because decorators are attached to the
declaration itself rather than inferred from a receiver's type. A shared layer
must keep `provenance_mechanism ∈ {REGISTRATION, ANNOTATION}` as a first-class
discriminator rather than flattening them.

## Discipline note

The temptation here was to call 85% recognition on Corpus A a success and
promote. Two things prevented that: Gate 1 explicitly requires *two*
mechanisms surviving real code, and Corpus B returned 0/14 — a complete
failure of the mechanism that R01 fixtures had marked ESTABLISHED for Express
and Fastify. That is precisely the fixture-to-production gap this milestone
was designed to expose, and it appeared exactly where R01's alias boundary
predicted it would.

Corpus B's 0% recognition with 0 false origins is, per the stated criterion,
a *better* result than a higher rate obtained by loosening inference — but it
is not promotion-worthy, because a provenance layer that abstains on an entire
mainstream framework is not yet general.
