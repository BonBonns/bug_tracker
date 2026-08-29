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

## evutil aggregation audit (`evutil_aggregation_audit.json`)

- raw V1 record: `abstained / required_evidence_absent`
- raw V2 record: `open_candidate / capacity_relation_not_established` (relationship_unresolved)
- merged physical identity: `(body.c, evutil_parse_sockaddr_port, line 25, col 9, memcpy buf,
  local char buf[128])`
- **canonical record = V2** (`open_candidate / relationship_unresolved`)
- **preserved provenance = [V1, V2]**
- route-selection rule: V2's enriched `relationship_unresolved` supersedes V1's
  `required_evidence_absent`; dedup cannot retain V1 because only V2's record is emitted, with
  V1 attached as provenance.

## Corrected full population (`corrected_vulnerable.jsonl` + `corrected_negative.jsonl`)

Post-hoc replay of the entire population on the archived CPGs with V2 canonical over V1
(`CORRECTED_SUMMARY.json`). It does NOT overwrite the original one-time run.

- 258 vulnerable rows + 101 negative rows; corrected runner + generator + cache-merkle + input
  hashes recorded.
- Recognition set INVARIANT: vulnerable 4→4, negative 3→3 (no labeled operations added or
  removed).
- Disposition changes: vulnerable **1** (`evutil_parse_sockaddr_port`: missing→open), negative
  **0** (checked, unchanged).

## Corrected claim (exact)

**The original one-time run misconfigured the runtime component by invoking V1 instead of the
declared V2.** A post-hoc replay on the archived CPGs established that the preregistered
recognition endpoint is **invariant** — no labeled operations were added or removed — but **one
vulnerable-site disposition changed from missing evidence to unresolved relationship**. Thus the
recognition result survives; the original route distribution required correction.

This is a harness-invocation correction (the scanner — V2 byte-identical to the frozen commit —
was never changed); it is stored explicitly as a post-hoc correction dataset, separate from the
original archived run. It is NOT claimed that the intended final scanner was evaluated in the
original run, nor that the corpus is untouched.
