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

## Contracts (tied to library + EXACT VALIDATED version + EXACT signature, not a name)

Five frozen contracts, each tied to a specific library, an EXACT validated version family (the
one the archived header actually validates — NOT extrapolated to a broader range), and an exact
signature. Each `write_extent` carries a DIRECTION — `max` (upper bound) or `exact` (lower/exact
bound):
- `lz4.LZ4_decompress_safe` (validated 1.9.4) — `int(const char*, char*, int, int)`; input=arg0,
  destination=arg1, input_length=arg2, **available_capacity=arg3** (`dstCapacity`, **max** bound).
- `lz4.LZ4_decompress_safe_partial` (1.9.4) — `int(const char*, char*, int, int, int)`;
  available_capacity=arg4 (**max**).
- `lz4.LZ4_decompress_fast` (1.9.4) — `int(const char*, char*, int)`; **exact_output_size=arg2**
  (`originalSize`, **exact**: the API writes exactly this many bytes). Deprecated/unsafe upstream.
- `zlib.inflate` (1.3.1) — `int(z_streamp, int)`; state_object=arg0.
- `zlib.deflate` (1.3.1) — `int(z_streamp, int)`; state_object=arg0.

**Call-shape gate (necessary, not sufficient):** a contract's shape matches a call ONLY when the
callee is NOT a user-defined same-named function AND the call arity equals the signature's
parameter count. A same-named local (even a signature-exact one with a body) and an arity
mismatch are left unbound.

**Library-identity provenance gate (required to APPLY a contract).** Name + arity + "no local
definition" is only a call SHAPE; it does not establish library identity (a same-named external
symbol could be another library, an interposed symbol, a project function in another translation
unit, or a same-signature look-alike). Applying a contract additionally requires an operator
**build attestation** of the linked library and version (`build_identity`, e.g.
`{"lz4":{"version":"1.9.4","established_by":"pinned_build"}}` — pinned build / linked package /
verified header). Without it → the call shape is RECOGNIZED but `contract_identity_unresolved`.
With library identity but a version not in the contract's `validated_versions` →
`contract_version_unresolved`. Only an attested version in the validated family applies the
contract. Version is never extrapolated from one archived header; a broader range would require
archiving+validating the boundary versions.

## Authoritative provenance (archived + hashed, fail closed)

Each contract's semantics are derived from an authoritative upstream header excerpt, sliced
VERBATIM from a pinned tag and archived under `cap_controls/cap4_contracts/authorities/` with
`PROVENANCE.json` recording, per excerpt: the upstream URL + tag, the full-file SHA-256 (so the
excerpt is re-verifiable by re-downloading that tag), the excerpt file's SHA-256, and the
prototype line. `load_contracts()` re-hashes every archived excerpt at load and DROPS any
contract whose excerpt is missing or altered (fail closed) — a contract is applied only while
bound to the exact authoritative text it was derived from. Five excerpts (safe, safe_partial,
fast; inflate, deflate). Sources: lz4 `lib/lz4.h` @v1.9.4 (`c1614ec…`), zlib `zlib.h` @v1.3.1
(`8a5579af…`). The archived excerpt validates only that version; `validated_versions` is not
widened beyond it.

## Method (all from frozen facts; roles by position + declaration identity)

- Every argument is mapped by POSITION into a role and resolved to its DECLARATION identity via
  Joern reference-target (`ref_target_ids`), never by name — destination, available_capacity,
  input, input_length, state_object.
- Destination capacity is bound ONLY from an independently-established fixed byte-array or
  literal-count byte allocation extent (stack `element_count`×byte-type, or heap
  `extent_in_bytes` with `element_width==1`); a param / struct field / alias / symbolic
  allocation stays UNRESOLVED, never assumed.
- **Write extent** per contract: `arg_bytes` with a DIRECTION (`max`/`exact`) — an explicit
  argument the caller passes (a literal byte count, or `sizeof(dst)` which binds to the exact
  capacity); or `state_field_prestate` (zlib `avail_out`).
- **An excessive MAXIMUM is not a proven overflow (the load-bearing fix).** A decoder's extent
  is a per-call bound with a direction: `max` means `actual_writes <= extent`; `exact`/`min`
  means `actual_writes >= extent`. `extent <= capacity` is always a deterministic in-capacity
  proof (for either direction). `extent > capacity`:
  - **exact/lower** bound → `proven_oversized` (the API WILL write `>= extent > capacity`; e.g.
    `LZ4_decompress_fast(originalSize=200)` into a 64-byte dst).
  - **max/upper** bound → `decoder_extent_exceeds_known_capacity` / `open_candidate` /
    relationship_unresolved. Allowing LZ4 up to 200 bytes into a 64-byte dst is an unsafe
    *configuration*, but the compressed input might decode to 20 bytes — we have NOT proven more
    than 64 are written, so it is NEVER `proven_oversized`.
- **PRE vs POST semantics.** zlib `avail_out` is REMAINING free capacity BEFORE the call and is
  DECREMENTED by the bytes written AFTER the call (`total_out` grows) — it is NOT bytes-written.
  Because that pre-state field is not tracked, an inflate/deflate call is RECOGNIZED with its
  write extent left unresolved (`decoder_capacity_in_state_object`), never mis-read as a written
  count. This satisfies "if the contract cannot establish a maximum write extent, recognize the
  operation but leave the relationship unresolved."
- Return codes, partial writes, statefulness, and callbacks are recorded on each contract and
  respected (e.g. LZ4's `<0` error path still writes `<= dstCapacity`; zlib is stateful/repeated).

## Controls (cap_decoder_contract_test.py, ALL PASS — 30/30)

Bounded (extent <= capacity, either direction): `dc_fits` (max 100 == 100), `dc_partial`
(safe_partial max 256 <= 256), `dc_sizeof` (`sizeof(dst)`), `dc_heap` (256-byte `malloc`,
heap_literal_allocation), `dc_fast_fits` (**exact** originalSize 50 <= 64) ->
deterministic_complete.
Extent direction (Fix 1): `dc_over` (LZ4 **max** dstCapacity 200 > 64-byte dst) ->
**open_candidate** `decoder_extent_exceeds_known_capacity` (unsafe config, NOT proven overflow);
`dc_fast_over` (LZ4_decompress_fast **exact** originalSize 200 > 64) -> **proven_oversized** (a
lower/exact bound above capacity is the only proven-overflow case).
Unresolved (recognized, never a false safe): `dc_symbolic` -> write_extent_unresolved;
`dc_param_dst` -> capacity_of_dest_unresolved; `dc_inflate` (zlib) ->
decoder_capacity_in_state_object (`extent_field=avail_out`, `meaning=pre_call_remaining_capacity`,
`stateful=true`).
Library identity (Fix 2): with NO build attestation every call shape is recognized but
`contract_identity_unresolved` (roles still mapped); with an attestation whose version is not in
the validated family (`lz4` version null, `zlib` 1.2.11) -> `contract_version_unresolved` and NO
bounded/oversized verdict; only the verified attestation (`lz4` 1.9.4, `zlib` 1.3.1) applies the
contracts.
Signature-not-name: `dc_arity` (3 vs 4) and `dc_local_deflate` (local, signature-exact, has a
body) -> not bound. Negative: `dc_notdecoder` (plain copy loop) -> no op.
Provenance fail-closed: a tampered `LZ4_decompress_safe` excerpt -> that contract dropped
(`hash_mismatch`), its calls unrecognized, while intact contracts (fast, partial, inflate) still
operate. Separation/additive: cap4 sites disjoint from the frozen cursor producer's; cap3 emits
nothing on the decoder controls; cap4 emits 0 ops on a bare-memcpy file.

## Reported metrics (synthetic development controls)

1. **Writes recognized** — 10 decoder operations across the controls (7 LZ4 incl. 2 fast, 1
   partial, 1 inflate); the 3 out-of-domain calls (arity mismatch, local shadow, plain loop)
   correctly recognized as NOT decoder contracts. Recognition (roles, extent semantics) happens
   even without provenance — only APPLICATION is gated.
2. **Capacity facts established** — destination byte capacity from a fixed array (dc_fits 100,
   dc_over/fast 64, dc_sizeof 100, dc_partial 256) or a literal byte allocation (dc_heap 256);
   parameter/struct-object destinations (dc_param_dst, dc_inflate) left UNRESOLVED.
3. **Relationships resolved** — extent <= capacity -> deterministic_complete; an EXACT/lower
   bound > capacity -> proven_oversized (dc_fast_over); a MAX/upper bound > capacity ->
   open_candidate / decoder_extent_exceeds_known_capacity (NOT proven); symbolic / state-object /
   unattested / unvalidated-version -> relationship_unresolved.
4. **Correct abstentions** — write_extent_unresolved, capacity_of_dest_unresolved,
   decoder_capacity_in_state_object (avail_out pre-state), decoder_extent_exceeds_known_capacity
   (max over capacity), contract_identity_unresolved (no attestation), contract_version_unresolved
   (unvalidated version) — each recognizes the operation without a promotion.
5. **No unsupported promotions** — a verdict is issued only on (a) an established+validated
   library identity via a build attestation, (b) an established destination capacity, and (c) a
   contract extent from a verified authoritative excerpt; an excessive MAX bound is never called
   proven-overflow, and the avail_out pre-state is never read as bytes-written.
6. **Existing verdicts changed outside the new domain — ZERO.** The cap4 gate re-runs the
   capability 1/2/3 gates (CAP1/2/3 controls PASS) and the frozen analysis-record-r01 gate
   (unchanged); cap4's sites are disjoint from the frozen cursor producer and from cap3's
   member-write sites; it emits nothing on non-decoder calls.

## Frozen

This is the final planned representation capability. Held-out measurement remains deferred: no
SecVulEval/Big-Vul/ARVO/pooled result inspected. After this gate freezes, the next step is the
one-time held-out recognition/recall measurement.
