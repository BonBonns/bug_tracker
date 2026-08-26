# JS-PROV-R25 — preregistered BEFORE implementation

## Scope
INTEGRATION only. R23b producer stays frozen (hash-checked). No semantic
change to either producer.

> Consume established `ImportBindingIdentityFact` records wherever the existing
> CommonJS `require_bindings.tsv` path supplies equivalent binding identity.

## Preregistered invariants
```text
I1  ImportBindingIdentityFact output hash-identical to R23b
I2  existing CommonJS results (Corpus B) unchanged
I3  no default/namespace case becomes established merely through wiring
I4  the 13 R23b abstentions remain abstentions
I5  no new member identity without a corresponding R23b ESTABLISHED record
I6  existing established origins cannot disappear
I7  WRONG = 0
I8  downstream movement reported BY LAYER and traced to the enabling fact
```

## Preregistered expectation (recorded before running)
63 established import identities exist on Corpus C. It is NOT expected that all
63 cause downstream facts. Predicted movement:

```text
L1 module/export identity : expected to RISE (this is the consumer being wired)
L2 returned-function      : expected 0 -- Corpus C has no wrapper-returned
                            middleware (R22 measured 0 with CommonJS too)
L3 framework registration : expected 0 -- NestJS, no router registrations
L5 context state flow     : expected 0 -- no Koa ctx middleware chain
L6 external input origin  : expected UNCHANGED at 20
```

## Decisive negative control
Feed the consumer an import observation R23b SAW but deliberately did NOT
establish (namespace / default / re-export). **Nothing downstream may move.**
This distinguishes consuming the semantic FACT from consuming the mere
PRESENCE of an import.
