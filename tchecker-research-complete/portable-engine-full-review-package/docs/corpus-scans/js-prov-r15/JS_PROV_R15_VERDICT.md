# JS-PROV-R15 — Module Export Identity Consumption in Callback Resolution

`context_state_flow.py` now consumes `ModuleExportIdentityFact`. JS-STATE untouched.

## Consumer rule, with both constraints enforced

```text
callback argument is a CALL
  -> ModuleExportIdentityFact keyed on THAT EXACT argument's call id
  -> exported method identity
  -> ReturnedFunctionIdentityFact (direct-return only)
  -> returned callback METHOD
```

1. **Explicit module/export identity is PREFERRED over frontend callee inference**
   at require-crossing calls. Every produced flow records
   `writer_identity_source`.
2. **Identity is never broadened by filename or name coincidence** — the lookup
   is an exact call-id match. No fuzzy fallback exists.

## Acceptance gates — all met

```text
R12 fixture: 14/14   unchanged
R14 fixture:  9/9    unchanged
  m1  -> `other` only; `validate` never reachable
  m2/m4 -> distinct module identities preserved
  m3  -> UNKNOWN (object-literal export members still unmodelled)
  42 as any -> UNKNOWN
Corpus B: validate(schema) callback identity reaches validate:<lambda>1
```

## Corpus B: the chain completes

```text
STATE FLOWS: 23      (was 0 at R12)
  by resolution:            MUST 23
  by writer identity source: MODULE_EXPORT_IDENTITY 23

validate.middleware::...  validatedData -> validatedData         MUST
validate.middleware::...  validatedData -> validatedData.email   MUST
validate.middleware::...  validatedData -> validatedData.token   MUST
```

Every flow is carried by the new identity path; none by frontend callee
inference. The whole chain — require specifier -> file -> export assignment ->
exported method -> returned lambda -> callback identity -> context write ->
`BEFORE_NEXT` ordering -> property-prefix join -> downstream read — now runs on
real application code.

## The 10-vs-9 discrepancy: named and classified

R10 characterized **10** wrapper-returned callbacks in the established
registrations; R14 resolved **9**. The missing one is now identified:

```text
 9x  validate(schema)                  -> RESOLVED
 1x  uploadMiddleware.single('file')   -> UNRESOLVED
```

`upload-file.middleware.js` ends with:

```js
module.exports = multer({ storage });
```

The exported value is the **return of a third-party factory call**, not an
identifier naming a declared function. There is no exported METHOD for
`ModuleExportIdentityFact` to resolve, and `ReturnedFunctionIdentityFact` has no
wrapper to traverse — the middleware is produced at runtime inside `@koa/multer`.

```text
CLASSIFICATION: EXPORT_RHS_IS_RUNTIME_CALL (out of model, correctly abstains)
```

This is a genuine model boundary, not a resolution bug. Coverage is therefore
**9/10 of wrapper-returned callbacks**, with the 10th accounted for.

## The per-property payoff is NOT achieved on Corpus B — and that is honest

```text
origin_family for all 23 flows: UNKNOWN
```

The anticipated result (`validatedData.email -> HTTP_BODY` distinct from
`validatedData.user -> DB_LOOKUP`) is **not** reached on real code. Cause:

```js
const { value, error } = await schema.validate(
  { ...ctx.request.body, ...ctx.query }, { ... });
ctx.validatedData = value;
```

The write's RHS is `value` — a **destructured local** produced by Joi's
`schema.validate()` over a **spread merge of body AND query**. Three unmodelled
hops sit between the external origin and the write: object spread, a
third-party validation call, and destructuring assignment.

The origin classifier correctly reports `UNKNOWN` rather than guessing
`HTTP_BODY`. Guessing would have been wrong twice over — the value derives from
body *and* query merged, so even a correct guess of "body" would have been
incomplete.

The fixture *does* demonstrate the per-property distinction
(`vBody -> HTTP_BODY`, `vQuery -> HTTP_QUERY`, `vDerived -> DERIVED_FROM_HTTP_BODY`,
siblings never joining). Corpus B simply routes its values through machinery
this milestone does not model.

# JS-PROV-R15 VERDICT

```text
CONSUMER RULE:           IMPLEMENTED. Exact call-id match only; explicit export
                         identity preferred over frontend callee inference;
                         no filename/name broadening.
R12 FIXTURE:             14/14 unchanged
R14 FIXTURE:              9/9 unchanged
CORPUS-B STATE FLOWS:    23 (was 0), all MUST, all MODULE_EXPORT_IDENTITY
WRAPPER COVERAGE:        9/10; the 10th is `module.exports = multer({storage})`
                         -> EXPORT_RHS_IS_RUNTIME_CALL, a model boundary
PER-PROPERTY ORIGINS:    NOT achieved on Corpus B. All 23 flows carry
                         origin_family=UNKNOWN because the write RHS is a
                         destructured local from a Joi call over a spread of
                         body AND query. Demonstrated on the fixture only.
PROMOTION_READY:         Structural chain — YES in the sense that it now runs
                         end-to-end on real code with every negative control
                         intact. ExternalInputOriginFact — NO: origins are
                         UNKNOWN on real code, which is precisely what that
                         fact would need to assert.
DOMINANT GAP:            Value-level dataflow through spread + third-party call
                         + destructuring, between an external origin and the
                         context write. This is the ORIGIN half of the problem;
                         the IDENTITY half (R03-R15) is now closed.
NEXT MILESTONE:          JS-PROV-R16 — Write-RHS Origin Dataflow. Narrow scope:
                         can `ctx.X = value` where `value` comes from
                         `{...ctx.request.body, ...ctx.query}` be established as
                         DERIVED_FROM_HTTP_BODY|HTTP_QUERY (a SET, per R04's join
                         semantics) without claiming equivalence through the
                         third-party call?
```

## Discipline note

23 flows on real code after twelve milestones at zero is a tempting number to
lead with. The more important line in this report is that all 23 carry
`origin_family = UNKNOWN`.

The chain that was built — module identity through higher-order callback
identity through middleware ordering to property-granular state joins — is real
and demonstrably correct on every negative control. But the thing a security
reader actually wants (`this value came from the request body`) is still not
established on Corpus B, because Joi's validation call and a destructuring
assignment sit in the way. Reporting the flow count without that caveat would
imply provenance the analysis has not earned.
