# Held-out harness-configuration correction: V2 stack-capacity producer was omitted

## Finding (audit of the three possibilities)

**Possibility #1 — CONFIRMED: the held-out runner omitted `oob_runtime_capacity_v2`.**
`heldout_run.py` loaded its producer set as `oob_cursor_write_verdict`, **`oob_runtime_capacity_verdict` (V1, heap-only)**, `oob_interprocedural_verdict`. The intended final scanner's runtime-capacity producer is **`oob_runtime_capacity_v2.analyze_operations_v2`** (the stack-capacity integration responsible for the 620-operation routing improvement, `V2_STACK_RESULTS.md` / `ROUTE_TRANSITION_MATRIX.md`). V2's hash **is** declared in `RUN_MANIFEST.json` (`producers_sha256.oob_runtime_capacity_v2 = b1867edf…`), but the runner never invoked it.

- NOT #2 (V2 ran but failed) — V2 works correctly when run (see the replay below).
- NOT #3 (dedup kept V1) — dedup never saw a V2 record because V2 was never called.

So the archived held-out run did **not** exercise the exact intended final scanner: it used V1's heap-only runtime-capacity producer in place of the V1+V2 stack-capacity integration.

## `evutil_parse_sockaddr_port` replay (raw records archived in `evutil_v1_v2_replay.json`)

`memcpy(buf, ip_as_string+1, len)`, `buf = char buf[128]`:

| producer | analysis_status | reason_code | route | capacity bound |
|---|---|---|---|---|
| **V1 (ran)** | abstained | `required_evidence_absent` | additional_evidence_required | — (heap-only; no allocation) |
| **V2 (intended)** | open_candidate | `capacity_relation_not_established` | semantic_relationship_review | **stack_fixed_array, 128×char (`128*sizeof(char)`)** |

The V1→V2 transition record establishes the stack capacity (128) and routes `relationship_unresolved` (capacity bound, length `len` symbolic) — the expected final-scanner result.

## Impact on the confirmatory measurement (computed from the cached CPGs, no re-scan)

V2 is an **additive enrichment over V1's recognized operations** — it does not form new operations. Across all 194 mapped labeled writes, the runtime-capacity producer emits a record at the labeled write on the **same 5 sites** under V1 and V2 (**0 new recognitions, 0 lost**). Cursor, interproc, and cap1–4 are unchanged.

- **Recognition COUNT: UNCHANGED.** Vulnerable conditional recall stays **4 / 118 = 3.39 %**; combined **7 / 194** (label-validity-adjusted **7 / 143**). The V2 omission did **not** change the confirmatory recognition number.
- **Dispositions: 1 of 7 recognized sites changes.** Only `evutil_parse_sockaddr_port`: V1
  `abstained/required_evidence_absent` → V2 `open_candidate/relationship_unresolved` (capacity
  established from the stack array; length symbolic). The other six are unchanged (`blosc_c`,
  `enc_untrusted_recvfrom`, `nsc_rle_decode`, `new_creator` are memcpy into **parameters** with
  no stack array — V2 has no stack extent either; `msg_parse_fetch` is a cursor op, not
  runtime-capacity).
- **Soundness conclusion HOLDS.** V2 produces **no** deterministic verdict either
  (`relationship_unresolved` is an abstention). Deterministic verdicts emitted on held-out code
  under both V1 and V2 = **0**; adjudication accuracy was not exercised under either.
- The **19 emission-gap** sites and the **28 unsupported-sink** sites are unaffected by V1→V2
  (their dests are struct-fields / parameters, not stack arrays, so V2 recognizes none of them).

## Disposition

- **The confirmatory recognition result `4/118` STANDS** as a recognition/coverage measurement:
  the intended V2 scanner recognizes the identical set. This document is the required
  documented correction; the number does not move.
- **One correction to the recorded dispositions**: under the intended V2 scanner,
  `evutil_parse_sockaddr_port` establishes capacity (stack `buf[128]`) and routes
  `relationship_unresolved`, not `required_evidence_absent`. The held-out `RESULT.md` /
  `DIAGNOSIS.md` all-abstain wording is annotated accordingly (1 of 7 recognized sites
  establishes capacity under V2; still 0 deterministic verdicts).
- **Harness fixed**: `heldout_run.py` now invokes `oob_runtime_capacity_v2.analyze_operations_v2`
  (the intended producer) instead of V1. The scanner itself was never changed — `V2` is
  byte-identical to the frozen commit and was always declared in the manifest.

This correction is computed from the frozen `cpp.json` cache (same frozen frontend 4.0.608) and
the frozen V2 producer; it is a harness-invocation correction, not a scanner change, so the
corpus's confirmatory status is preserved.
