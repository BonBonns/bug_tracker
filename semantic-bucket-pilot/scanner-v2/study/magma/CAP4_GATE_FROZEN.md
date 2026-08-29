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

Seven frozen contracts, each tied to a specific library, an EXACT validated version family (the
one the archived header/spec actually validates — NOT extrapolated to a broader range), and an
exact signature. Each `write_extent` carries a DIRECTION — `max` (upper bound: `actual <= U`),
`exact` (`actual == E`), or `min` (lower bound: `actual >= L`):
- `lz4.LZ4_decompress_safe` (validated 1.9.4) — `int(const char*, char*, int, int)`;
  available_capacity=arg3 (`dstCapacity`, **max**).
- `lz4.LZ4_decompress_safe_partial` (1.9.4) — available_capacity=arg4 (**max**).
- `lz4.LZ4_decompress_fast` (1.9.4) — required_output_size=arg2 (`originalSize`). This is a
  **max** bound (malformed input makes it stop early and return `<0`, so `actual <= originalSize`)
  PLUS a **destination precondition** (`dst >= originalSize`). It is NOT an unconditional exact
  write. Deprecated/unsafe upstream.
- `zlib.inflate` / `zlib.deflate` (1.3.1) — `int(z_streamp, int)`; state_object=arg0.
- `synthetic_testonly.synth_fill_exact` / `synth_fill_atleast` (1.0.0, SYNTHETIC test-only) —
  `void(char*, int)`; arg1 is an **exact** / **min** UNCONDITIONAL write count. These exist ONLY
  to exercise exact/lower-bound routing with a genuinely unconditional write, since no real
  decoder guarantees one (they can stop early on malformed input). Their authority is the
  archived synthetic spec; no real-source scan carries an attestation for this library.

**Call-shape gate (necessary, not sufficient):** a contract's shape matches a call ONLY when the
callee is NOT a user-defined same-named function AND the call arity equals the signature's
parameter count. A same-named local (even a signature-exact one with a body) and an arity
mismatch are left unbound.

**Library-identity provenance gate (required to APPLY a contract) — trusted, scan-bound.** Name +
arity + "no local definition" is only a call SHAPE; it does not establish library identity (a
same-named external symbol could be another library, an interposed symbol, a project function in
another translation unit, or a same-signature look-alike). Library identity is established ONLY
through a **build attestation delivered on a trusted, scan-bound channel** — a
`build_attestation.json` emitted into the scan output directory by the scan pipeline, NOT
caller-supplied contract JSON. `load_build_attestation` REJECTS it (treats it as absent) unless
it is fingerprinted to THIS scan (its recorded `cpp.json`/`cpg.bin` SHA-256 match the analyzed
artifacts, so it cannot be replayed against another scan). For each library it carries a
`header_sha256` of the header the build actually used; a contract is applied ONLY when the
attested version is in `validated_versions` AND that `header_sha256` matches the archived
authority's full-file hash for that version (`_prov_fingerprints`). States:
`contract_identity_unresolved` (no/rejected attestation), `contract_version_unresolved` (version
not validated), `contract_build_fingerprint_mismatch` (build used a different header than the
one validated). Version is never extrapolated from one archived header.

## Authoritative provenance (archived + hashed, fail closed)

Each contract's semantics are derived from an authoritative upstream header excerpt, sliced
VERBATIM from a pinned tag and archived under `cap_controls/cap4_contracts/authorities/` with
`PROVENANCE.json` recording, per excerpt: the upstream URL + tag, the full-file SHA-256 (so the
excerpt is re-verifiable by re-downloading that tag), the excerpt file's SHA-256, and the
prototype line. `load_contracts()` re-hashes every archived excerpt at load and DROPS any
contract whose excerpt is missing or altered (fail closed) — a contract is applied only while
bound to the exact authoritative text it was derived from. Seven contracts over six excerpts
(safe, safe_partial, fast; inflate, deflate; one synthetic spec shared by the two synthetic
contracts). Sources: lz4 `lib/lz4.h` @v1.9.4 (`c1614ec…`), zlib `zlib.h` @v1.3.1 (`8a5579af…`),
and the archived synthetic spec (`4a874ca…`). The archived excerpt validates only that version;
`validated_versions` is not widened beyond it. The build attestation's per-library `header_sha256`
is checked against these full-file hashes, so a contract applies only if the analyzed build used
the validated header.

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
- **Bound-direction matrix (the load-bearing fix).** A decoder's extent is a per-call bound with
  a direction, and the routing is exactly:

  | Contract knowledge | extent ≤ capacity | extent > capacity |
  |---|---|---|
  | **max** (`actual ≤ U`) | deterministic_complete | unresolved (unsafe config / precondition) |
  | **exact** (`actual = E`) | deterministic_complete | proven_oversized |
  | **min** (`actual ≥ L`) | **UNRESOLVED** (L below capacity says nothing about the true max) | proven_oversized |

  The corrected cells: a **min** bound `≤ capacity` is NOT deterministic
  (`lower_bound_below_capacity_inconclusive`) — actual writes are `≥ L` with no known maximum, so
  safety is not established; and a **max** bound `> capacity` is NOT proven_oversized
  (`decoder_extent_exceeds_known_capacity`) — the input might decode to far less. Only an
  `exact`/`min` bound `> capacity` yields `proven_oversized`.
- **`LZ4_decompress_fast` is not an unconditional exact write.** `originalSize` is a destination
  PRECONDITION (`dst >= originalSize`) and an UPPER bound on writes (malformed input stops it
  early with `<0`). So `originalSize <= capacity` → deterministic_complete (upper bound within
  dst); `originalSize > capacity` → `decoder_destination_precondition_violated` / open_candidate
  (unsafe / contract-invalid, but not a proven overflow — it may stop before exceeding the
  buffer). **No real decoder in the registry yields `proven_oversized`**; that route is exercised
  only by the SYNTHETIC unconditional contracts, never manufactured on a real API.
- **PRE vs POST semantics.** zlib `avail_out` is REMAINING free capacity BEFORE the call and is
  DECREMENTED by the bytes written AFTER the call (`total_out` grows) — it is NOT bytes-written.
  Because that pre-state field is not tracked, an inflate/deflate call is RECOGNIZED with its
  write extent left unresolved (`decoder_capacity_in_state_object`), never mis-read as a written
  count. This satisfies "if the contract cannot establish a maximum write extent, recognize the
  operation but leave the relationship unresolved."
- Return codes, partial writes, statefulness, and callbacks are recorded on each contract and
  respected (e.g. LZ4's `<0` error path still writes `<= dstCapacity`; zlib is stateful/repeated).

## Controls (cap_decoder_contract_test.py, ALL PASS)

Bound-direction matrix — all six cells: **max** `dc_fits` (100<=100) -> deterministic,
`dc_over` (200>64) -> open `decoder_extent_exceeds_known_capacity` (NOT oversized); **exact**
`dc_synth_exact_fits` (50<=64) -> deterministic, `dc_synth_exact_over` (200>64) ->
**proven_oversized**; **min** `dc_synth_atleast_below` (>=50 into 64) -> open
`lower_bound_below_capacity_inconclusive` (NOT deterministic), `dc_synth_atleast_over` (>=200
into 64) -> **proven_oversized**. `LZ4_decompress_fast`: `dc_fast_fits` (originalSize 50<=64) ->
deterministic (upper bound within dst); `dc_fast_over` (200>64) -> open
`decoder_destination_precondition_violated` (unsafe/contract-invalid, not proven). Other bounded:
`dc_sizeof`, `dc_heap`, `dc_partial` -> deterministic. No real-decoder `proven_oversized` — that
route is reached only by the synthetic unconditional contracts.
Unresolved (recognized, never a false safe): `dc_symbolic` -> write_extent_unresolved;
`dc_param_dst` -> capacity_of_dest_unresolved; `dc_inflate` -> decoder_capacity_in_state_object
(`extent_field=avail_out`, `pre_call_remaining_capacity`, `stateful=true`).
Trusted scan-bound channel: NO attestation -> `contract_identity_unresolved` (shape recognized,
roles mapped); a WRONG scan fingerprint -> attestation REJECTED (identity unresolved — not
caller-replayable); attested version not in the validated family -> `contract_version_unresolved`;
build `header_sha256` != authority -> `contract_build_fingerprint_mismatch`; only the verified,
scan-bound, fingerprint-matching attestation applies the contracts.
Signature-not-name: `dc_arity` (3 vs 4) and `dc_local_deflate` (local, signature-exact, body) ->
not bound. Negative: `dc_notdecoder` -> no op. Provenance fail-closed: a tampered
`LZ4_decompress_safe` excerpt -> that contract dropped (`hash_mismatch`), its calls unrecognized,
intact contracts still operate. Separation/additive: cap4 sites disjoint from the frozen cursor
producer's; cap3 emits nothing on the decoder controls; cap4 emits 0 ops on a bare-memcpy file.

## Reported metrics (synthetic development controls)

1. **Writes recognized** — 14 decoder operations across the controls (safe/partial/fast, inflate,
   and the synthetic exact/min pairs, each in fits/over forms); the 3 out-of-domain calls (arity
   mismatch, local shadow, plain loop) correctly recognized as NOT decoder contracts. Recognition
   (roles, extent semantics) happens even without provenance — only APPLICATION is gated.
2. **Capacity facts established** — destination byte capacity from a fixed array or a literal byte
   allocation (dc_heap 256); parameter/struct-object destinations (dc_param_dst, dc_inflate) left
   UNRESOLVED.
3. **Relationships resolved (correct matrix)** — deterministic_complete only for max/exact `<=`
   capacity; proven_oversized only for exact/min `>` capacity (synthetic contracts only); a max
   `>` capacity or a min `<=` capacity is open/unresolved, never a verdict.
4. **Correct abstentions** — write_extent_unresolved, capacity_of_dest_unresolved,
   decoder_capacity_in_state_object (avail_out pre-state), decoder_extent_exceeds_known_capacity
   (max over cap), decoder_destination_precondition_violated (fast precondition),
   lower_bound_below_capacity_inconclusive (min below cap), and the identity states
   (contract_identity_unresolved / contract_version_unresolved / contract_build_fingerprint_mismatch).
5. **No unsupported promotions** — a verdict is issued only on (a) library identity established
   through the trusted scan-bound + fingerprinted build attestation, (b) an established
   destination capacity, and (c) the correct bound-direction cell. An excessive MAX bound is never
   called proven-overflow, a lower bound below capacity is never called safe, and the avail_out
   pre-state is never read as bytes-written. No real decoder yields proven_oversized.
6. **Existing verdicts changed outside the new domain — ZERO.** The cap4 gate re-runs the
   capability 1/2/3 gates (CAP1/2/3 controls PASS) and the frozen analysis-record-r01 gate
   (unchanged); cap4's sites are disjoint from the frozen cursor producer and from cap3's
   member-write sites; it emits nothing on non-decoder calls.

## Frozen

This is the final planned representation capability. Held-out measurement remains deferred: no
SecVulEval/Big-Vul/ARVO/pooled result inspected. After this gate freezes, the next step is the
one-time held-out recognition/recall measurement.
