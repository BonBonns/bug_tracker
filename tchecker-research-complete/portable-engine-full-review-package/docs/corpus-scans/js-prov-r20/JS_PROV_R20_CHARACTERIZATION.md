# JS-PROV-R20 — NestJS Decorator Origin Characterization

**Characterization only.** No implementation, no promotion. Chosen ahead of a
validator-semantics profile because decorators encode the source family at the
controller boundary, with no opaque transform in the way.

## Why this path is qualitatively different

```text
Koa/Joi:   HTTP_BODY + HTTP_QUERY -> opaque Joi transform -> output UNKNOWN
NestJS:    @Body() parameter      -> HTTP_BODY ESTABLISHED -> locals -> sink
```

This is the first path that could carry a **strong** origin fact rather than
only transform-input evidence.

## Q1 — Decorator identity and parameter binding: **FAITHFUL**

The adversarial fixture makes every identifier name contradict its decorator:

```text
a1  @Query() body      -> idx1:body     -> [Query]      (NOT Body)
a2  @Body()  query     -> idx1:query    -> [Body]       (NOT Query)
a3  @Param('id') headers -> idx1:headers -> [Param]     (NOT Headers)
a4  @Headers('h') param  -> idx1:param   -> [Headers]   (NOT Param)
a5  @Body()  banana    -> idx1:banana   -> [Body]
a6  @Query() orange    -> idx1:orange   -> [Query]
```

**The origin comes from the annotation, never the identifier name.** All four
misleading cases bind correctly. This is a materially stronger position than
the Koa path, where R13's `T2` control had to prove the *absence* of a
name-based rule; here the decorator is positive evidence in its own right.

## Q2 — Families distinguishable, unrelated parameters silent

```text
a7  @Body() body, unrelated: any   ->  idx1:body->[Body]   idx2:unrelated->[NONE]
a8  @Param('id') id, @Body() b, @Query() q
        -> idx1:id->[Param]  idx2:b->[Body]  idx3:q->[Query]
```

Three distinct families on one method, each bound to its own parameter index.
An undecorated parameter receives **nothing** — no default, no inheritance from
its siblings.

## Q3 — Negative controls: silent

```text
NotAController (identical shape, no decorators)  ->  classAnn=[]  all methods ann=0
TController.helper (undecorated method in a decorated class) -> UNDECORATED
```

A class with the same method and parameter shape but no decorators produces no
annotations at all, and an undecorated method inside a decorated controller is
correctly excluded.

## Q4 — Alias and destructuring: **traceable, via existing machinery**

```text
@Body() b
  const alias = b        ->  ASSIGN  const alias = b
  const { field } = b    ->  ASSIGN  _tmp_0 = b ;  field = _tmp_0.field
  parameter REF'd by identifiers: b@25, b@26
```

Both lower to ordinary assignments over a parameter that is REF-linked from its
uses — the same shapes JS-PROV-R13 (destructuring) and R12/R19 (property paths)
already handle. No new machinery is implied.

## Q5 — What the frontend does NOT preserve

**Decorator arguments are not recovered.** `@Param('id')` and `@Headers('h')`
report `parameterAssign = 0` and no AST children; only the raw `code` string
carries the key:

```text
Param    code=@Param('id')    paramAssigns=0  children=<none>
Headers  code=@Headers('h')   paramAssigns=0  children=<none>
```

The **family** (`Param`, `Headers`) is fully recoverable; the **specific key**
(`'id'`, `'h'`) is only present as text inside `code`. Consequences:

- `HTTP_PATH_PARAM` / `HTTP_HEADER` as a family: establishable.
- *Which* path param or header: **not** establishable without parsing the
  annotation's code string, which per the standing discipline (R13: "code
  strings are not identities") should not be done.
- `@Body()` and `@Query()` are unaffected — they take no key in the common form.

No fabrication or erasure was observed elsewhere: every decorator present in
source appeared on the correct parameter, and no decorator appeared where none
was written.

## Real corpus replay — `gobeam/truthy` @ `9b9a61be`

```text
route methods = 39
  BODY = 16   QUERY = 6   PARAM = 12   HEADERS = 0
  other decorators = 16   (@Req, @Res, @GetUser, @UploadedFile)
```

Exactly matching source ground truth measured independently in JS-PROV-R02
(16/6/12/0). The 16 "other" decorators are correctly **not** classified as HTTP
input families — `@GetUser` and `@UploadedFile` are application- or
framework-specific and would need their own characterization.

**34 parameters across 39 route methods carry an establishable HTTP origin
family on real code**, with no transform between the decorator and the
parameter.

# JS-PROV-R20 VERDICT

```text
DECORATOR IDENTITY:        PRESERVED. Class, method and parameter annotations
                           all recoverable.
PARAMETER BINDING:         FAITHFUL, by index. Verified against four
                           deliberately misleading identifier names.
FAMILY DISCRIMINATION:     Body / Query / Param / Headers distinguishable;
                           multiple families on one method bind independently.
UNRELATED PARAMETERS:      Receive NOTHING. No default, no sibling inheritance.
NEGATIVE CONTROLS:         Silent. Undecorated class of identical shape and
                           undecorated method in a decorated class both yield
                           no annotations.
ALIASES / DESTRUCTURING:   Traceable via existing REF + assignment machinery.
FABRICATION / ERASURE:     None observed.
NOT PRESERVED:             Decorator ARGUMENTS. `@Param('id')` exposes no
                           parameterAssign and no AST children; the key exists
                           only inside the annotation's code string. Family is
                           establishable; the specific key is NOT, and should
                           not be recovered by parsing code text.
REAL CORPUS:               truthy 39 route methods; BODY 16 / QUERY 6 /
                           PARAM 12 / HEADERS 0, matching R02 ground truth
                           exactly. 34 parameters with establishable origin.

PROMOTION_READY:           NO (characterization milestone; nothing implemented).
                           But the evidence supports promoting
                           ExternalInputOriginFact on this path -- the first
                           route where `established = true` is defensible
                           WITHOUT a third-party semantics profile.
DOMINANT GAP:              Decorator argument keys (family-level only).
                           Secondary: application-specific decorators
                           (@GetUser, @UploadedFile) are uncharacterized and
                           must stay UNKNOWN, not be guessed from their names.
NEXT MILESTONE:            JS-PROV-R21 — ExternalInputOriginFact promotion on
                           the NestJS decorator path. Fact shape:
                             value = parameter identity
                             origin_family = HTTP_BODY | HTTP_QUERY |
                                             HTTP_PATH_PARAM | HTTP_HEADER
                             evidence = NESTJS_PARAMETER_DECORATOR
                             established = true
                           Acceptance: the four misleading-name teeth; unrelated
                           parameter silent; undecorated class silent;
                           application-specific decorators UNKNOWN not guessed;
                           truthy replay 16/6/12/0; all existing gates unchanged.
                           Then second-corpus replay, then (last, riskiest)
                           curated joi/zod/yup semantics.
```

## Discipline note

This is the cleanest characterization result in the JS-PROV line — every tooth
passed on the first run, which has not happened before. That is itself worth
noting rather than celebrating: the decorator path is easy precisely because
NestJS states the answer declaratively, so it exercises far less of the
inference machinery than the Koa path did. A clean result here is weaker
evidence about the *engine* than a messy result was.

The one real limitation found (decorator arguments absent) was found only by
probing for it after the headline teeth already passed.
