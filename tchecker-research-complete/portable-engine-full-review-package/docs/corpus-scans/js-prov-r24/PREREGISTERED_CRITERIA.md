# JS-PROV-R24 — corpus eligibility, preregistered BEFORE candidate inspection

Recorded prior to searching, so selection cannot drift toward whatever happens
to fire. Corpus C (R22) mostly measured *absence of opportunity*; R24 must not
repeat that.

## Structural eligibility — ALL required

```text
E1  Koa application (not a library/middleware package)
E2  @koa/router or koa-router route registrations present   (Layer 3 opportunity)
E3  >= 8 route registrations                                (non-trivial sample)
E4  middleware chain: >= 1 route with 2+ callback arguments  (Layer 4)
E5  ctx.<property> WRITE by one middleware and READ by another (Layers 5/7)
E6  CommonJS module style (require + module.exports)         (Layers 1/2)
E7  independently authored -- not paralect/koa-api-starter, not a fork of it
```

## Preregistered success criterion

NOT "everything fires". Success is:

```text
same semantic conditions  -> same facts
absent conditions         -> principled abstention with a named category
demonstrably wrong        -> 0
```

## Preregistered failure categories

`FRONTEND_GAP`, `MODULE_IDENTITY_GAP`, `FRAMEWORK_REGISTRATION_GAP`,
`CALLBACK_IDENTITY_GAP`, `STATE_FLOW_GAP`, `ORIGIN_PRODUCER_GAP`,
`OPAQUE_TRANSFORM`, `EXPECTED_UNSUPPORTED`, `WRONG_EVIDENCE`

## Frozen

No implementation changes. No import-fact wiring (that is a separate later
revision, deliberately excluded so it cannot contaminate this experiment).
