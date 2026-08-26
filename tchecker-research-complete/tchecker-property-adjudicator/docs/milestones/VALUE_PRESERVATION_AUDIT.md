# Value-preservation audit — false-positive exposed by the complete packet

The complete code-bearing packet exposed that the emails.js/normalizeEmail serialize-DoS
candidate is a FALSE POSITIVE. reachableByFlows established data-dependence REACHABILITY,
not attacker-VALUE preservation. A new audit classifies every edge of the established path
by semantic flow kind (CPG structure only) and finds the first edge where attacker-value
preservation is no longer established.

## New producer: export_value_flow_audit.sc
Edge kinds: VALUE_PRESERVING_FLOW, VALUE_TRANSFORM (resolved def), PROPERTY_READ,
ARGUMENT_TO_PARAMETER (preserving); LOOKUP_KEY_INFLUENCE, CONTROL_DEPENDENCE (decisive
breaks); RECEIVER_OR_ARG_ARTIFACT, RETURN_VALUE_DEPENDENCE, UNKNOWN (non-decisive noise).
The argument-into-sink edge (JSON.stringify) is value-preserving (serialized).

## emails.js / normalizeEmail  ->  FALSE POSITIVE
Attacker value is live: request.payload -> _tmp.email -> email -> normalizeEmail(email)
-> normalizedEmail  (VALUE_TRANSFORM). Then it BREAKS:
  seq17  LOOKUP_KEY_INFLUENCE   db.getSecondaryEmail(normalizedEmail)
normalizedEmail is a LOOKUP KEY; the returned existingRecord is a DB record, not attacker
value. The path then crosses a COMPARISON:
  butil.buffersAreEqual(existingRecord.uid, uid)   (CONTROL_DEPENDENCE)
and reachableByFlows stitches to the independent parameter `uid`. Confirmed by targeted CPG
dataflow: the serialized fields are
  uidStr = String(uid),  uid = sessionToken.uid  (authenticated session, NOT request.payload)
  secret = random.hex(16)
Neither serialized field is attacker-derived. Attacker input only influences a lookup and a
control/comparison decision. -> serialize-DoS NOT ESTABLISHED. The LLM is NOT asked whether
normalizeEmail bounds size (a moot question on this path).

## Genuine candidates (value preserved to the sink; firstBreak = -1)
  customs.js  JSON.stringify(requestData): sanitizePayload returns clonePayload={...payload};
              attacker payload (minus authPW/oldAuthPW/paymentToken) is serialized. GENUINE.
  123done/server.js  JSON.stringify(req.body) direct. GENUINE.
  post-nimbus, 123done/oauth.js  direct req.* -> stringify. GENUINE.

## New validity gate (adjudicator)
A serialize-DoS candidate is valid only if some established origin preserves attacker value
to the sink. value_preservation in {ESTABLISHED, NOT_ESTABLISHED, NOT_AUDITED}. NOT_ESTABLISHED
-> disposition REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED, unresolved properties emptied, no
LLM question. Verified: fixture ESTABLISHED (unchanged disposition), customs.js ESTABLISHED,
emails.js NOT_ESTABLISHED (rejected). No frozen producer changed; this is an added gate.

## Experiment impact
- Experiment 2 (body-context ablation, emails.js/normalizeEmail) is INVALID: it was built on
  a false-positive path. Scrapped. Do not run it.
- Experiment 1 (customs.js/sanitizePayload) remains valid: value preservation ESTABLISHED and
  the transform identity/definition is genuinely UNKNOWN, so the evidence-boundary calibration
  test still holds. (Note: customs.js is itself a genuine serialize-DoS.)

This is the payoff of adding real source->sink code: we can now check whether the security
question even follows from the path, instead of handing the LLM an elaborate description of a
potentially invalid path.
