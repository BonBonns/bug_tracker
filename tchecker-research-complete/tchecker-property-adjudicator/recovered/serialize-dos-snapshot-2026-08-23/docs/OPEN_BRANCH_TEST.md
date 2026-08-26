# OPEN-branch generalization test (property propagation + trace identity + semantic review together)

The node-http-proxy case tested the direct branch; the novu case reached BROKEN via a spurious
stitch, pre-empting OPEN. This case isolates the OPEN branch with a narrow acceptance criterion:
    request-derived source -> ONE user-defined member-method transform -> sink,
    with NO nearby comparison/error/control-flow branch that could create a competing stitched path.

Because real handlers almost always wrap transforms in control flow (the novu confound itself), this
is a CONTROLLED held-out isolation on a realistic idiom (audit-cache write of a request body through
a member method), TypeScript, run through the frozen pipeline without tuning. It complements — does
not replace — the real-code evidence (trace identity already generalized on novu).

## Two variants, one shape (differ only in the transform body)
  PRESERVES: redactSecrets(body){ const clone={...body}; delete clone['password']; delete clone['token']; return clone; }
  BREAKS:    digestBody(body){ return createHash('sha256').update(JSON.stringify(body)).digest('hex'); }
Both: req.body -> this.<method>(req.body) -> cleaned -> JSON.stringify(cleaned)   (no branch)

## Observed (all four target signals, both variants)
| signal | PRESERVES | BREAKS |
|---|---|---|
| property outcome            | OPEN | OPEN |
| trace identity              | UNIQUE (redactSecrets) | UNIQUE (digestBody) |
| subject_transform           | TRACE-established | TRACE-established |
| semantic packet has exact callee body | yes | yes |

## Semantic resolution depends on the body (as intended)
| variant | correct semantic effect | supplied answer | disposition |
|---|---|---|---|
| PRESERVES (no size bound; {...body} minus 2 keys) | attacker size survives (UNSAFE) | UNSAFE | RESOLVED_CANDIDATE_BY_ACCEPTED_HINT |
| BREAKS (fixed-length sha256 hex)                   | size bounded (SAFE)              | SAFE   | RESOLVED_SAFE_BY_ACCEPTED_HINT |

This is the full OPEN -> trace-identity -> semantic-review generalization, exercised end-to-end on
out-of-corpus TypeScript, with both possible semantic outcomes.

## Integration bug this test EXPOSED and FIXED
The trace-backed body was COMPUTED (def_code) but not reaching the semantic packet: the relevant-code
inclusion checked `def_status == "ESTABLISHED"`, while trace identity sets "ESTABLISHED_BY_TRACE".
So the packet carried the callsite but not the exact body — violating the Step 4 invariant that the
exact trace-linked body is the body supplied to adjudication.

Fix (completing Step 4's integration, not redesigning it): the inclusion now accepts
"ESTABLISHED_BY_TRACE" and tags its provenance TRACE_BACKED_EXACT_CALLEE. After the fix both packets
carry the exact body. Regression: customs.js, fixture, emails.js, bodyDecoder, amb all unchanged.

This is exactly the value of exercising the OPEN branch: it was the first path to actually consume
the trace-backed body downstream, and it revealed the body was not being delivered to the packet.

## Exact-body handoff — explicit assertions (mechanism demonstrated, not inferred)

Call-node identity chain (must be one node end to end):
    property_open_edge.call_node == trace_identity.call_node == adjudication.subject_call_node
    redactSecrets: 30064771079 == 30064771079 == 30064771079   PASS
    digestBody:    30064771082 == 30064771082 == 30064771082   PASS

Body correspondence (per variant):
    body supplied to adjudication == body emitted for the uniquely identified callee
    supplied def_status = ESTABLISHED_BY_TRACE, provenance = TRACE_BACKED_EXACT_CALLEE
    redactSecrets: supplied body == trace body, and body IS the redactSecrets definition   PASS
    digestBody:    supplied body == trace body, and body IS the digestBody definition       PASS

Resulting clean evidence:
    redactSecrets: OPEN -> TRACE identity -> exact body -> semantic says property survives -> candidate
    digestBody:    OPEN -> TRACE identity -> exact body -> semantic says hash bounds -> safe

## Preserved: the two failures that preceded the passing assertions
These are kept as evidence that the identity/body correspondence was TESTED, not assumed:
1. Call-node mismatch. The first run picked the transform's call_node by code-match, which resolved
   to a DIFFERENT node (…078) than the trace producer's enclosing-call node (…079). Result:
   subject_transform stayed UNKNOWN and the HIGH-confidence answer was NOT accepted (CANDIDATE_OPEN).
   Aligning transform_identity.call_node to the trace_identity.call_node fixed it — proving the
   adjudicator genuinely keys identity by call node, and that the chain equality above is load-bearing.
2. Body not delivered to the packet. Even after the chain matched, the exact body was absent from the
   semantic packet because relevant-code inclusion checked `def_status == "ESTABLISHED"` and trace
   sets "ESTABLISHED_BY_TRACE". The body-correspondence assertion FAILED until the inclusion was
   fixed to accept ESTABLISHED_BY_TRACE. Only then did "supplied body == trace-emitted callee body"
   pass. This is the Step 4 integration bug the OPEN branch existed to catch.

## Stop point
Both directions of the OPEN branch are demonstrated, including exact callee identity and exact body
handoff. Per plan, fixture-building stops here. The next meaningful work is real-candidate
exploitability (the vulnerability-level residual questions now recorded on ESTABLISHED candidates)
or broader held-out evaluation — not more synthetic cases.
