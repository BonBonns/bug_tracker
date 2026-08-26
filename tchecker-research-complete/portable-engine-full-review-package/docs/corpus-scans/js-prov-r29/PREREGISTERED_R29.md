# JS-PROV-R29 — preregistered BEFORE implementation

## Scope (narrow)
`framework_registration.py` currently consumes receiver-domain evidence ONLY for
PARAMETER receivers (`if not param_method: continue`). Accept ALSO a receiver
whose **own resolved type** is in the framework profile.

Nothing else. No profile expansion, no new frameworks, no downstream changes.

## Why this is not a weakening
The receiver type is already present and CORRECT on Corpus D
(`type = koa-router`, 15 sites). R09 was not being cautious about it -- it never
looked. The framework profile remains the same closed, curated table; the only
change is which evidence source may satisfy it.

## Preregistered invariants
```text
K1  Corpus B unchanged at 14 registrations (parameter-receiver path untouched)
K2  Corpus D reaches 15 (its 15 router.<verb> sites)
K3  a directly-typed receiver whose type is NOT in the profile yields 0
K4  an ANY-typed direct receiver yields 0 (no guessing)
K5  the R09 fake-router controls still abstain (installFake etc.)
K6  identity_evidence distinguishes the two sources:
        RECEIVER_DOMAIN_EVIDENCE      (parameter, via ObservedParameterTypeFact)
        DIRECT_RECEIVER_TYPE          (local, own resolved type)
K7  methodFullName / resolved callee still NEVER consulted (JS-PROV-R07)
K8  WRONG = 0
K9  all gates green
```

## Decisive negative control
A local receiver with a plausible framework-shaped API but a NON-profiled type
(`class FakeRouter { get(){} }`, `const fr = new FakeRouter()`) must produce
NO registration, even though `fr.get("/x", handler)` is syntactically identical
to a real one.
