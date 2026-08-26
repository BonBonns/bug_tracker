# JS-PROV-R01 — Shared External-Input Provenance Coverage Characterization

**Characterization only.** `ExternalInputOriginFact` NOT promoted. R07/R10/R12
unchanged. No framework-name heuristics added.

Question: how broadly does R13's provenance mechanism generalize across real
JS/TS frameworks?

Core invariant enforced throughout: an origin may be established only from
**positive structural provenance** (module identity → registration/API
identity → handler identity → parameter role → property path). **Names are
never sufficient.**

---

## Framework object identity — the load-bearing measurement

Type recovery resolves every framework receiver back to its module, and
separates the negative control by *type shape*, not by name:

```text
app           type=express:<returnValue>
router        type=express:Router:<returnValue>
fastify       type=fastify
koaApp        type=koa
hapiServer    type=@hapi/hapi:server:<returnValue>
notFramework  type={ post: (p: ANY, cb: ANY) => ANY; }   <-- object literal, NOT module-derived
```

This is the discriminator the whole layer rests on: a module-derived
`methodFullName` prefix vs. a structural object-literal type. `notFramework`
has a method literally named `post` taking `(path, callback)` and is still
cleanly excluded.

## Per-framework results

| Framework | Registration `methodFullName` | Handler identity |
|---|---|---|
| Express | `express:<returnValue>:post` | `METHOD_REF -> <lambda>0` |
| Express Router | `express:Router:<returnValue>:get` | `METHOD_REF -> <lambda>1` |
| Fastify | `fastify:post` | `METHOD_REF -> <lambda>2` |
| Koa | `koa:use` | `METHOD_REF -> <lambda>3` |
| Hapi | `@hapi/hapi:server:<returnValue>:route` | handler nested in object literal |
| NestJS | *(no registration call — decorators)* | see below |
| Serverless | *(none)* | see below |

```text
EXPRESS
  IMPORT_IDENTITY: ESTABLISHED       FRAMEWORK_OBJECT_IDENTITY: ESTABLISHED
  REGISTRATION_CALL_IDENTITY: ESTABLISHED   HANDLER_IDENTITY: ESTABLISHED
  REQUEST_PARAMETER_ROLE: ESTABLISHED (idx1 after implicit `this`)
  RESPONSE_PARAMETER_ROLE: ESTABLISHED (idx2)
  BODY/QUERY/PATH_PARAMS/HEADERS/COOKIES: ESTABLISHED (distinct property paths)

EXPRESS ROUTER    identical to Express, distinct type (express:Router:<returnValue>)

FASTIFY
  IMPORT/OBJECT/REGISTRATION/HANDLER: ESTABLISHED
  REQUEST_PARAMETER_ROLE: ESTABLISHED (idx1, named `request` — name NOT used)
  RESPONSE_PARAMETER_ROLE: ESTABLISHED (idx2, `reply`)
  BODY/QUERY/PATH_PARAMS/HEADERS: ESTABLISHED    COOKIES: UNKNOWN (not exercised)

KOA
  IMPORT/OBJECT/REGISTRATION/HANDLER: ESTABLISHED (koa:use)
  REQUEST_PARAMETER_ROLE: PARTIAL — idx1 is `ctx`, a CONTEXT object, not a
    request object. Body is `ctx.request.body` (nested) while query/headers are
    `ctx.query`/`ctx.headers` (direct). Koa's context model does not match the
    (req, res) shape and needs its own property-path model.
  RESPONSE_PARAMETER_ROLE: N/A — idx2 is `next`, not a response.
  BODY: PARTIAL (nested path)   QUERY/HEADERS: ESTABLISHED
  COOKIES: PARTIAL — `ctx.cookies.get("c")` is a CALL, not a property read.

HAPI
  IMPORT_IDENTITY / FRAMEWORK_OBJECT_IDENTITY / REGISTRATION_CALL_IDENTITY:
    ESTABLISHED (@hapi/hapi:server:<returnValue>:route)
  HANDLER_IDENTITY: PARTIAL — the handler is a member of an object literal
    argument ({ method, path, handler }), NOT a positional METHOD_REF. The
    handler method IS reachable in the CPG (fw.js::program:handler,
    params 0:this,1:request,2:h) but linking it to the registration requires
    object-literal member traversal, which was not demonstrated here.
  REQUEST_PARAMETER_ROLE: ESTABLISHED once the handler is located (idx1)
  BODY: `request.payload` (Hapi-specific name) — distinct path, needs its own
    family mapping.  QUERY/PATH_PARAMS/HEADERS: ESTABLISHED.
  COOKIES: `request.state` — Hapi-specific, PARTIAL.

NESTJS  — different mechanism entirely, and it works well
  IMPORT_IDENTITY: ESTABLISHED (`@nestjs/common`)
  FRAMEWORK_OBJECT_IDENTITY: N/A — no framework object; decorator-based
  REGISTRATION_CALL_IDENTITY: N/A — no registration call
  HANDLER_IDENTITY: ESTABLISHED via ANNOTATIONS:
      class UsersController  annotations=[Controller]
      method login           annotations=[Post]
  REQUEST_PARAMETER_ROLE: ESTABLISHED via PARAMETER ANNOTATIONS — and this is
    stronger than positional inference:
      param body  annotations=[Body]
      param q     annotations=[Query]
      param id    annotations=[Param]
      param h     annotations=[Headers]
  BODY/QUERY/PATH_PARAMS/HEADERS: ESTABLISHED — the annotation names the
    origin family directly. COOKIES: UNKNOWN (not exercised).
  NOTE: this is a SECOND, independent provenance mechanism (annotation-based),
  not a variant of the registration-based one. A shared layer must model both.

SERVERLESS (AWS Lambda shape)
  IMPORT_IDENTITY: UNKNOWN — no framework import at all
  FRAMEWORK_OBJECT_IDENTITY / REGISTRATION_CALL_IDENTITY: UNKNOWN
  HANDLER_IDENTITY: UNKNOWN — only `exports.handler = async (event, context)`,
    an assignment to an export whose *name* is the sole anchor.
  RESULT: NOT ESTABLISHABLE without a name heuristic, which the core invariant
    forbids. Correctly ABSTAINS. Establishing this would require an external
    deployment-manifest anchor (serverless.yml / SAM / CDK), i.e. evidence
    outside the source graph entirely.
```

---

## Negative controls — all silent

| Control | Result |
|---|---|
| `fake(req, res)` unregistered lookalike | never a registration argument → **not established** |
| `fakeFastify(request, reply)` lookalike | same → **not established** |
| `notFramework.post("/n1", cb)` same method name, non-framework | `mfn={ post: ... }:post` — object-literal type, not module-derived → **not established** |
| wrong callback parameter (`res.locals.x`) | reads idx**2**, positionally distinct from idx1 → **not a request source** |
| unrelated object with `.body` (`plain.body.username`) | not a handler parameter → **not established** |
| helper receiving ordinary object (`ordinaryHelper(obj)`) | param idx1 with no registration provenance → **not established** |

All six silent. The critical one (`notFramework`) is excluded on *type shape*,
which is the correct structural reason.

---

## Wrapper / forwarding / middleware

```text
router.post("/w1", namedHandler)
    arg2 IDENT namedHandler  type=fw.js::program:namedHandler     ESTABLISHED

router.post("/w2", mw, namedHandler)                              ESTABLISHED
    arg2 IDENT mw            type=fw.js::program:mw
    arg3 IDENT namedHandler  type=fw.js::program:namedHandler
    -> multiple callback arguments both resolve; position distinguishes them

router.post("/w3", reexported)      // const reexported = namedHandler
    arg2 IDENT reexported    type=ANY                             BREAKS
```

**Concrete boundary found:** a single alias assignment (`const reexported =
namedHandler`) **loses the function type entirely** (`ANY`). Named references
and middleware chains survive; re-exported/aliased handlers do not. Per
instruction, this is characterized rather than patched with interprocedural
inference.

---

## Destructuring and aliasing — all four forms survive

```text
const { body } = req;          ->  _tmp_7 = req ;  body = _tmp_7.body
const { username } = req.body; ->  _tmp_8 = req.body ;  username = _tmp_8.username
const b2 = req.body;           ->  const b2 = req.body
const x2 = b2.username;        ->  const x2 = b2.username
```

Every form lowers to ordinary assignments over field accesses, traceable with
existing REF/assignment facts. Destructuring introduces a `_tmp_N`
intermediate, which is an extra hop but fully connected. No new machinery
required.

---

## Source-family separation — maintained, not collapsed

```text
HTTP_BODY        req.body / request.body / ctx.request.body / request.payload / @Body()
HTTP_QUERY       req.query / ctx.query / @Query()
HTTP_PATH_PARAM  req.params / ctx.params / @Param()
HTTP_HEADER      req.headers / ctx.headers / @Headers()
HTTP_COOKIE      req.cookies / ctx.cookies.get(...) / request.state
```

Each family is a distinct property path per framework. Note the paths differ
*per framework* (Hapi `payload` vs Express `body`), so a shared layer needs a
per-framework family mapping, not one global path table.

```text
PROCESS_ENV   process.env.SECRET    paths visible; NO registration anchor
CLI_ARGV      process.argv[2]       paths visible; NO registration anchor
EVENT_PAYLOAD (serverless)          NOT ESTABLISHABLE (see above)
```

For these three the required positive anchor would be **module identity of the
`process` global / deployment manifest**, not route registration. They should
not be forced into the HTTP model. Characterized, not claimed.

---

## Real-code spot checks

Partially satisfied, and I am flagging this as the weakest part of this
milestone rather than overstating it.

- **Express — real code, validated in JS-STATE-R13:** the `tarkov-data-manager`
  vulnerable commit resolved end-to-end
  (`express:express:<returnValue>:post` → `METHOD_REF <lambda>4` → idx1 →
  `req.body.username`). That is one real codebase on one framework.
- **Second framework on real code: NOT DONE.** A second real repository using
  Fastify/Koa/Hapi/NestJS was not scanned in this pass. The promotion gate's
  real-code requirement is therefore **only half met**, and the per-framework
  results above rest on minimal fixtures, not production code.

---

# JS-PROV-R01 VERDICT

```text
EXPRESS:      ESTABLISHED (fixture + real code)
FASTIFY:      ESTABLISHED (fixture only)
KOA:          PARTIAL — registration/handler ESTABLISHED, but ctx-based
              context model needs its own property-path family mapping
HAPI:         PARTIAL — framework/registration ESTABLISHED, handler identity
              needs object-literal member traversal (not demonstrated)
NESTJS:       ESTABLISHED via a SECOND, independent mechanism (class/method/
              parameter ANNOTATIONS), stronger than positional inference —
              @Body/@Query/@Param/@Headers name the origin family directly
SERVERLESS:   NOT ESTABLISHABLE — no import, no registration, only an export
              name. Correctly abstains. Needs an out-of-source anchor.

ALIASING:            ESTABLISHED (all forms lower to REF-traceable assignments)
DESTRUCTURING:       ESTABLISHED (via _tmp_N intermediate, fully connected)
WRAPPER_FORWARDING:  ESTABLISHED for named references; BREAKS on a single
                     alias re-export (type collapses to ANY)
MIDDLEWARE:          ESTABLISHED (multi-callback args resolve; position
                     distinguishes middleware from handler)

NEGATIVE_CONTROLS:   ALL SILENT (6/6). The critical `notFramework.post` case is
                     excluded on TYPE SHAPE (object-literal vs module-derived
                     methodFullName), not on names.

REAL-CODE VALIDATION: PARTIAL — Express validated on real code (R13 anchor);
                     no second framework validated on real code.

PROMOTION_JUSTIFIED: NO — but narrowly, and for one reason only.

  Gate 1 (>=2 independent framework families positively established): MET
        Express + Express Router + Fastify + NestJS, and NestJS via an
        independent annotation mechanism.
  Gate 2 (negative controls silent): MET (6/6)
  Gate 3 (identity from registration/framework evidence, not names): MET
  Gate 4 (aliases/destructuring preserve origin): MET
  Gate 5 (unknown frameworks abstain): MET (serverless abstains correctly)
  Real-code validation across >=2 frameworks: **NOT MET**

  Four of five formal gates pass and the mechanism generalizes better than
  expected. Promotion is withheld solely because every non-Express result
  rests on minimal fixtures. Fixtures demonstrate that a mechanism CAN work;
  they do not establish that it works on production code, and this project
  has already been burned once (JS-STATE-R07: 31/31 synthetic, 0 real
  positives across 3 corpora).

DOMINANT GAP:  REAL-CODE VALIDATION BREADTH, not mechanism. Secondary
               mechanism gaps, in priority order: (a) Hapi object-literal
               handler traversal, (b) Koa ctx property-family model,
               (c) alias re-export type collapse to ANY, (d) non-HTTP
               families lack any positive anchor.

NEXT MILESTONE: JS-PROV-R02 — Multi-Framework Real-Code Provenance
               Validation. Scan >=2 real repositories on DIFFERENT frameworks
               (one Fastify or NestJS, one Koa or Hapi). Report per repo:
               handlers examined / structurally recognized / request params
               correctly identified / false-positive lookalikes / UNKNOWN
               handlers, with manual adjudication of a sample of BOTH
               recognized and unrecognized handlers. Promote
               ExternalInputOriginFact only if the fixture results survive
               contact with production code.
```

## Architectural payoff (if R02 validates)

R12 becomes one consumer among many:

```text
ExternalInputOriginFact  (neutral: origin_family, framework_family,
                          registration_call_id, handler_identity,
                          parameter_position, property_path, derivation_chain)
        |
        +--> prototype-reachable property read -> runtime-domain widening
        |    -> coercive auth comparison            (the R12/Tarkov chain)
        +--> SSRF / path traversal / command exec / SQLi / XSS readers
```

The provenance layer must never emit `attacker_controlled = true`. It reports
origin; the security reader decides whether that origin meets its definition
of attacker control.

## Discipline note

The strongest result here was unplanned: **NestJS works via a completely
different mechanism** (annotations) that is *more* precise than the
registration/position chain, because `@Body()`/`@Query()` name the origin
family directly rather than requiring it to be inferred from a property path.
A shared layer must model both mechanisms rather than assuming the Express
shape generalizes.

The withheld promotion is deliberate. Four of five gates pass, but this
project has already demonstrated that synthetic success predicts real-world
value poorly. One more milestone of real-code validation is cheap insurance
against promoting a fact that looks general and isn't.
