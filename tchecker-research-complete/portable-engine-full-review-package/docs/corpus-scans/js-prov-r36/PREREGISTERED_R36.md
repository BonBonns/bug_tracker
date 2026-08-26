# JS-PROV-R36 — preregistered BEFORE implementation

## Scope: the two remaining pieces, which are COUPLED
```text
(a) SELECTOR RESOLUTION (Defect A's T2b, left open by R33)
    `require(spec).member` -> resolve to the member's OWN module,
    instead of merely refusing the binding.
    This USES R35's export_member_alias -- it cannot be done before R35.

(b) CONSUMER INTEGRATION
    context_state_flow's callback resolution consumes (a) + R35's alias,
    so `ctrl.get` reaches articles-controller.js:get.
```
Producers R14/R25/R31/R33/R35 are frozen and hash-verified. No new extraction.

## Preregistered teeth
```text
S1  `require("./outer").inner` RESOLVES to ./inner (no longer merely refused)
S2  SHARED-NAME CONTROL (R33 fixture): `ctrl.shared` must reach
    inner.js:innerShared and NEVER outer.js:outerShared
S3  unresolved selection (`.nope`) still ABSTAINS -- no module fallback
S4  bare `require("./outer")` unchanged
C1  Corpus D: callback identity for `ctrl.get` reaches
    articles-controller.js:get
C2  Corpus D L4/L5 movement PERMITTED, not required; any new fact traced
C3  no export-abstained member may move downstream (R25 decisive negative)
N   Corpus B IDENTICAL on ALL ENUMERATED layers:
      L1 module-identity 48, L3 registrations 18, L5 flows 23 all MUST,
      import-binding 0, validate() 9
W   demonstrably wrong = 0; all gates green
```

## Claim discipline
If (a) lands but Corpus D L4/L5 stay 0, R36 still succeeds on S1-S4 and the
chain stays blocked for a NEW named reason, which must be stated. Movement is
not the success criterion; correct resolution is.
