# Capability 4 — external decoder contracts (FROZEN gate)

Runnable gate `gate_capability_4.py` -> `CAP4_GATE=PASS`. Frontend joern-c2cpg v4.0.608.
No model calls. Synthetic adversarial controls only (Magma/PNG003 would be development
evidence only); the frozen held-out corpus is NOT referenced (enforced by grep in the gate).
Implementation: `cap_decoder_contract.py`.

## Scope (deliberately narrow)

A library decoder/decompressor call writes into a caller-provided destination buffer, where
the number of bytes written is governed by the API's DOCUMENTED CONTRACT, not by a memcpy-style
length argument. Capability 4 recognizes such calls and — only when the contract lets it bound
the per-call MAXIMUM write extent against an independently-established destination capacity —
routes them; otherwise it recognizes the operation and leaves the relationship UNRESOLVED. It
never claims VULNERABLE and never claims safe without a proof. Additive: emits
`attribution="call_site_summary"`, `capability="decoder_contract"` records whose sites are
library-decoder calls that Capabilities 1–3 and the frozen producers never route.

## Contracts (tied to library + version + EXACT signature, not a name)

Four frozen contracts, each tied to a specific library, version-range, and exact signature:
- `lz4.LZ4_decompress_safe@v1.7.0+` — `int(const char*, char*, int, int)`; roles input=arg0,
  destination=arg1, input_length=arg2, **available_capacity=arg3** (`dstCapacity`).
- `lz4.LZ4_decompress_safe_partial@v1.8.3+` — `int(const char*, char*, int, int, int)`;
  available_capacity=arg4.
- `zlib.inflate@v1.2.0+` — `int(z_streamp, int)`; state_object=arg0.
- `zlib.deflate@v1.2.0+` — `int(z_streamp, int)`; state_object=arg0.

A contract binds a call ONLY when the callee is NOT a user-defined same-named function AND the
call arity equals the signature's parameter count. A same-named local (even one whose signature
matches exactly) and an arity mismatch are both left unbound — the contract is tied to the
library API, not the name.

## Authoritative provenance (archived + hashed, fail closed)

Each contract's semantics are derived from an authoritative upstream header excerpt, sliced
VERBATIM from a pinned tag and archived under `cap_controls/cap4_contracts/authorities/` with
`PROVENANCE.json` recording, per excerpt: the upstream URL + tag, the full-file SHA-256 (so the
excerpt is re-verifiable by re-downloading that tag), the excerpt file's SHA-256, and the
prototype line. `load_contracts()` re-hashes every archived excerpt at load and DROPS any
contract whose excerpt is missing or altered (fail closed) — a contract is applied only while
bound to the exact authoritative text it was derived from. Sources: lz4 `lib/lz4.h` @v1.9.4
(`c1614ec…`), zlib `zlib.h` @v1.3.1 (`8a5579af…`).

## Method (all from frozen facts; roles by position + declaration identity)

- Every argument is mapped by POSITION into a role and resolved to its DECLARATION identity via
  Joern reference-target (`ref_target_ids`), never by name — destination, available_capacity,
  input, input_length, state_object.
- Destination capacity is bound ONLY from an independently-established fixed byte-array or
  literal-count byte allocation extent (stack `element_count`×byte-type, or heap
  `extent_in_bytes` with `element_width==1`); a param / struct field / alias / symbolic
  allocation stays UNRESOLVED, never assumed.
- **Max write extent** per contract: `arg_bytes` (an explicit capacity argument the caller
  passes — a literal byte count, or `sizeof(dst)` which binds to the exact capacity); or
  `state_field_prestate` (zlib `avail_out`). The bound is a per-call MAXIMUM (an upper bound
  that holds across partial / early-exit / repeated-call paths), never an exact count, so it can
  DISPROVE safety (oversized) or establish an in-capacity upper bound, never assert a precise
  write.
- **PRE vs POST semantics.** zlib `avail_out` is REMAINING free capacity BEFORE the call and is
  DECREMENTED by the bytes written AFTER the call (`total_out` grows) — it is NOT bytes-written.
  Because that pre-state field is not tracked, an inflate/deflate call is RECOGNIZED with its
  write extent left unresolved (`decoder_capacity_in_state_object`), never mis-read as a written
  count. This satisfies "if the contract cannot establish a maximum write extent, recognize the
  operation but leave the relationship unresolved."
- Return codes, partial writes, statefulness, and callbacks are recorded on each contract and
  respected (e.g. LZ4's `<0` error path still writes `<= dstCapacity`; zlib is stateful/repeated).

## Controls (cap_decoder_contract_test.py, ALL PASS)

Bounded: `dc_fits` (dstCapacity 100 == 100-byte dst) and `dc_partial` (safe_partial arg4 256 <=
256) -> deterministic_complete; `dc_sizeof` (`sizeof(dst)`) -> deterministic_complete (extent
bound to exact capacity); `dc_heap` (256-byte `malloc`) -> deterministic_complete
(heap_literal_allocation). Oversized: `dc_over` (dstCapacity 200 for a 64-byte dst) ->
proven_oversized (the decoder is told it may write past the buffer). Unresolved (recognized,
never a false safe): `dc_symbolic` (variable capacity) -> write_extent_unresolved; `dc_param_dst`
(param destination) -> capacity_of_dest_unresolved; `dc_inflate` (zlib) ->
decoder_capacity_in_state_object with `extent_field=avail_out`,
`meaning=pre_call_remaining_capacity`, `stateful=true`. Signature-not-name: `dc_arity` (3 args
vs 4) and `dc_local_deflate` (local function matching the deflate signature exactly, but with a
body) -> NOT bound (no op). Negative: `dc_notdecoder` (plain copy loop) -> no op. Provenance
fail-closed: a tampered `LZ4_decompress_safe` excerpt -> that contract is dropped
(`hash_mismatch`), its calls are not routed, while the intact contracts (safe_partial, inflate)
still operate. Separation/additive: cap4's decoder-call sites are disjoint from the frozen
cursor producer's; cap3 emits nothing on the decoder controls; cap4 emits 0 ops on a bare-memcpy
file.

## Reported metrics (synthetic development controls)

1. **Writes recognized** — 8 decoder operations across the controls (6 LZ4, 1 partial, 1
   inflate); the 3 out-of-domain calls (arity mismatch, local shadow, plain loop) correctly
   recognized as NOT decoder contracts.
2. **Capacity facts established** — destination byte capacity from a fixed array (dc_fits 100,
   dc_over 64, dc_sizeof 100, dc_partial 256) or a literal byte allocation (dc_heap 256);
   parameter/struct-object destinations (dc_param_dst, dc_inflate) left UNRESOLVED.
3. **Relationships resolved** — bounded (extent <= capacity) -> deterministic_complete;
   over-capacity (extent > capacity) -> proven_oversized; every symbolic/state-object case ->
   relationship_unresolved.
4. **Correct abstentions** — write_extent_unresolved (symbolic capacity),
   capacity_of_dest_unresolved (unknown destination), decoder_capacity_in_state_object (zlib
   avail_out pre-state) — each recognizes the operation without a promotion.
5. **No unsupported promotions** — a verdict is issued only on an established destination
   capacity AND a contract-bounded max write extent from a verified authoritative excerpt; the
   avail_out pre-state is never read as bytes-written.
6. **Existing verdicts changed outside the new domain — ZERO.** The cap4 gate re-runs the
   capability 1/2/3 gates (CAP1/2/3 controls PASS) and the frozen analysis-record-r01 gate
   (unchanged); cap4's sites are disjoint from the frozen cursor producer and from cap3's
   member-write sites; it emits nothing on non-decoder calls.

## Frozen

This is the final planned representation capability. Held-out measurement remains deferred: no
SecVulEval/Big-Vul/ARVO/pooled result inspected. After this gate freezes, the next step is the
one-time held-out recognition/recall measurement.
