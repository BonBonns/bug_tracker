# JS-PROV-R21 — ExternalInputOriginFact Promotion (NestJS decorator producer)

`JS_PROV_R21=12/12`. Real corpus reproduces R02's independent baseline exactly.
**`ExternalInputOriginFact` is now promoted**, with NestJS parameter decorators
as its first `established = true` producer.

## Frozen mapping — family level only

```text
@Body()        -> HTTP_BODY
@Query()       -> HTTP_QUERY
@Param(...)    -> HTTP_PARAM
@Headers(...)  -> HTTP_HEADERS

evidence    = NESTJS_PARAMETER_DECORATOR
established = true
origin_key  = UNKNOWN        <-- ALWAYS, never parsed from annotation code
```

`origin_key` is explicit rather than silently omitted. R20 measured that
`@Param('id')` exposes no `parameterAssign` and no AST children, so the key
exists only inside the annotation's code string — and code strings are not
identities (R13). The gate asserts `origin_key == UNKNOWN` on every fact.

## Negative controls — all load-bearing, all passing

R20 proved four cases where a name-based fallback gives the **wrong** family.
Each is now a permanent gate assertion:

```text
@Query()   named `body`     -> HTTP_QUERY    (not BODY)
@Body()    named `query`    -> HTTP_BODY     (not QUERY)
@Param()   named `headers`  -> HTTP_PARAM    (not HEADERS)
@Headers() named `param`    -> HTTP_HEADERS  (not PARAM)
undecorated sibling parameter        -> NOTHING (no name fallback)
undecorated class of identical shape -> NOTHING
undecorated method in a decorated class -> NOTHING
```

## Boundary vs dataflow — kept separate

Framework evidence stays at the boundary. A local derived from a decorated
parameter does **not** receive a fresh decorator fact:

```text
@Body() b                -> ExternalInputOriginFact(HTTP_BODY,
                              evidence=NESTJS_PARAMETER_DECORATOR, established)
const alias = b          -> derived: evidence=DATAFLOW_FROM_ESTABLISHED_ORIGIN
```

Two gate assertions enforce this: the derived local must consume the boundary
fact, and **no** derived entry may claim `NESTJS_PARAMETER_DECORATOR` evidence.

## Real corpus — `gobeam/truthy` @ `9b9a61be`

```text
established facts : 34
  HTTP_BODY 16   HTTP_QUERY 6   HTTP_PARAM 12   HTTP_HEADERS 0
  all origin_key UNKNOWN : true

UNKNOWN decorators (never guessed from their names):
  @GetUser x7   @Req x4   @Res x4   @UploadedFile x1
```

**16/6/12/0 reproduces JS-PROV-R02's independently-measured source ground truth
exactly.** That baseline was established before this producer existed, so it is
not a self-referential success criterion.

The 16 application- and framework-specific decorators are correctly reported as
`UNKNOWN` with reason `DECORATOR_NOT_IN_CLOSED_SET` — not guessed. `@GetUser`
in particular *does* carry request-derived data in this application, and
guessing it would have been right by accident and wrong as a rule.

`derived: 0` on truthy — the controllers pass decorated parameters straight to
services rather than aliasing them locally, so the derived path is exercised by
the fixture only.

# JS-PROV-R21 VERDICT

```text
MAPPING:              Family level, closed set of four. Frozen.
ORIGIN KEY:           Explicitly UNKNOWN on every fact; never parsed.
NEGATIVE CONTROLS:    12/12, including all four misleading-name cases.
BOUNDARY/DATAFLOW:    Separated and gate-enforced.
REAL CORPUS:          34 established facts, 16/6/12/0 — exact match to R02's
                      independent baseline. 16 non-HTTP decorators UNKNOWN.
UNKNOWN DECORATORS:   Never guessed. @GetUser/@Req/@Res/@UploadedFile.

PROMOTION:            ExternalInputOriginFact PROMOTED.
                      First established producer: NESTJS_PARAMETER_DECORATOR.
                      Koa/Joi path correctly REMAINS at TRANSFORM_INPUT_ONLY —
                      the same neutral fact, different evidence strength per
                      framework path.

DOMINANT GAP:         Decorator argument keys (family-level only). Secondary:
                      application-specific decorators uncharacterized by design.
NEXT MILESTONE:       Second-corpus replay of the WHOLE chain (the R02 lesson:
                      one corpus is not generalization), then — last and
                      riskiest — curated joi/zod/yup value-preservation
                      semantics, which would convert Koa's TRANSFORM_INPUT_ONLY
                      into DERIVED_FROM_* only where a library is explicitly
                      characterized and versioned.
```

## Thesis note

The same neutral fact is now produced through two structurally unrelated
evidence chains:

```text
Koa:     module -> callback -> middleware role -> state write -> transform
                -> TRANSFORM_INPUT_ONLY
NestJS:  decorator -> parameter
                -> ESTABLISHED
```

That contrast is the useful result. It shows the fact model is genuinely shared
while evidence strength stays framework- and path-specific — and it shows that
what a framework *declares* determines how much a static analyzer must
*reconstruct*. NestJS volunteers at the boundary what Koa forced Fable to
rebuild across fourteen milestones.

## Discipline note

R21 passed cleanly, but the R20 caution carries forward: this path is easy
because NestJS states the answer. The promotion is real, and it is narrow —
`established = true` holds for decorated parameters on this framework, not for
external input in general.

The one judgement call worth naming: `@GetUser` in truthy genuinely carries
request-derived data, so classifying it `UNKNOWN` loses real information. That
is the correct trade — a closed set that abstains is maintainable; an open set
that infers families from decorator names is the lexical heuristic this entire
line was built to avoid.
