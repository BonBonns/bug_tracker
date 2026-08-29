# Seven-field trace of the 54 producer-reaching sites (analysis only)

The 54 mapped confirmed-destination-writes that reached the producers: 47 non-emitting + 7
emitted. Built from the cached `cpp.json` (no re-scan, no scanner change). Machine-readable data:
`trace54.json`. Seven fields per site: target identity · write form matched · destination
identity established · capacity established · write length established · relationship established ·
emitted route/reason.

## Correction to the earlier gate labels (my classification was too broad)

The producers' ACTUAL recognized sink set is `callee_contracts.CALLEE_CONTRACTS` =
`{memcpy, memmove, wmemcpy, PORT_Memcpy, PORT_Memmove, PORT_Memset, HMAC_Finish}`. Plain
`memset`, `snprintf`, `sprintf`, `strcpy`, `strncpy` are NOT recognized. My diagnostic's `COPY`
set was broader, so the earlier "39 missing-capacity + 8 capacity-established" gate split was
imprecise. Re-split against the real contract set, the 47 are:

- **A — 19 : recognized callee (memcpy family) + capacity ABSENT → SILENT DROP.** The producer
  recognizes `memcpy` but forms no operation because the dest has **no reaching allocation** in
  the packet (dest is a param / struct-field / local without a malloc). It emits **nothing**.
  This is the emission-gap the fix targets: it SHOULD emit `required_evidence_absent` naming the
  missing capacity requirement so the operation is visible to the router. (Contrast: the 5
  emitted `required_evidence_absent` recognized sites DID have a reaching allocation candidate —
  that is why they emitted a record and the 19 did not.)
- **B — 0 : recognized callee + capacity ESTABLISHED but no record.** There are **no** such
  cases. The hypothesized "producer-to-router wiring failure for the 8" does **not** exist among
  memcpy-family sinks.
- **C — 28 : UNSUPPORTED sink/form (not in the contract set).** `memset` 10, `snprintf` 6,
  `sprintf` 4, `strcpy` 2, `strncpy` 2, non-sink 4. These are silent-dropped because the callee
  is not a recognized sink — an add-a-contract / add-a-model gap, not a wiring bug. (The earlier
  "8 capacity-established" were all in here: e.g. `snprintf` into a stack buffer whose extent my
  detector found but the heap-oriented producer never consults.)

So the 47 = **19 emission-gap (memcpy, no reaching allocation) + 28 unsupported-sink/form + 0
wiring**. All 47 are SILENT DROPS (no producer emits any record for the labeled operation).

## Recheck of the one recognized site with an established extent — CONFIRMED mis-reason

`evutil_parse_sockaddr_port`: `memcpy(buf, ip_as_string+1, len)` where `buf` is `char buf[128]`.
- **Capacity established: YES** — `buf` is a stack fixed array of 128 bytes, bound to the exact
  memcpy dest.
- Write length: **symbolic** (`len`).
- Heap allocations in the function: none.
- Emitted: `oob_runtime_capacity_verdict / required_evidence_absent`.

**`required_evidence_absent` is the wrong reason here.** The capacity evidence is present (stack
`buf[128]`); the real blocker is the symbolic length. The correct route is
**`relationship_unresolved`** (known capacity 128 vs symbolic length `len` → relation not
established), not "required evidence absent" (which asserts the capacity evidence is missing).
Root cause: a **producer boundary** — `oob_runtime_capacity_verdict` consults only HEAP
allocations (`CALLEE_CONTRACTS` + `allocation_extent`); it recognizes the `memcpy` but ignores
the stack-array extent (known to `v2.compute_stack_fixed_array_extents`, used by cap1/cap2), so
it mis-reports an established stack capacity as absent evidence.

## Seven-field trace summary (full rows in trace54.json)

- **A (19)** target=param/struct-field/local · form=`copy_sink:memcpy` · dest-id=established ·
  capacity=**absent** · length=symbolic (17) / literal (2) · relationship=no · emitted=**SILENT
  DROP** → should be `required_evidence_absent`.
- **C (28)** form=`memset`/`snprintf`/`sprintf`/`strcpy`/`strncpy`/non-sink · capacity=absent
  (heap) · emitted=**SILENT DROP** → unsupported sink/form.
- **Emitted (7)** all abstain: `required_evidence_absent` ×4 (evutil mis-reasoned, see above),
  `destination_identity_ambiguous` ×1 (cursor, non-vuln msg_parse_fetch),
  `unknown_allocator_contract` ×1 (new_creator), plus cursor `required_evidence_absent` ×1
  (msg_parse_fetch vuln). **None reached a verdict.**

## Corrected conclusion (per the requested wording)

The earlier phrasing "no adjudication false positives/negatives" is replaced by: **adjudication
accuracy was NOT exercised, because the scanner emitted zero deterministic vulnerability/safety
verdicts on held-out code. Zero opportunities is not evidence of zero adjudication errors.**

## Engineering priorities implied (future work; would consume this corpus as development data)

1. **Emission/routing (19):** a recognized `memcpy` with no reaching allocation should emit
   `required_evidence_absent` (naming the missing capacity), not silently drop. Also fix the
   producer-boundary mis-reason (evutil): a memcpy into a known stack array should consult the
   stack extent and route `relationship_unresolved` when the length is symbolic — not
   `required_evidence_absent`.
2. **Unsupported sinks/forms (28 + the 89 unmapped-domain):** add contracts for
   `memset`/`snprintf`/`sprintf`/`strcpy`/`strncpy` and general index-write / pointer-dereference
   models.
3. **Parsing (69):** improve function-packet parsing or move to full-repository builds to supply
   the declarations/macros/attributes that currently collapse 88 % of the missing writes.
4. **Corpus construction:** exclude declarations / guards / comments (23 % label noise) up front.

Post-hoc adjusted recognition denominator (cleanest for debugging): **7 / 143 = 4.90 %**. The
original frozen **4 / 118 = 3.39 %** remains the confirmatory result.
