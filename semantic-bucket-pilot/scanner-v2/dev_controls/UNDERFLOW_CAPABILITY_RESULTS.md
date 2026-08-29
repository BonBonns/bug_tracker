# Underflow-fed-length capability -- built, validated (synthetic + real-world)

Follow-up to `UNDERFLOW_CAPABILITY_DESIGN.md` (now built: `cap_underflow_length.py`,
`cap_underflow_length_test.py`, `cap_controls/underflow/`). This note records the two
validation passes the design doc's own plan called for.

## Synthetic controls: 11/11 PASS

`cap_underflow_length_test.py` against `cap_controls/underflow/underflow.c` (8 functions,
run through the real frozen joern pipeline, not a mocked facts dict):

- real dominating+controlling guard -> credited `deterministic_complete`
- no guard at all -> `open_candidate`
- guard on the WRONG operand pair -> not falsely credited
- compound-adjustment guard (`if (headerLen - 4 < mdBlockSize)`) -> never credited
- assert-only guard (compiled out in release) -> NOT credited
- direct-inline vs one-hop-through-a-local resolution, both recognized
- array-index variant of both credited/uncredited
- every `open_candidate` carries `llm_eligible=True` + `route=range_arithmetic_review`;
  every `deterministic_complete` carries `llm_eligible=False` + no route
- no-regression: 0 ops when a subtraction feeds neither a sink width arg nor an index

## Real-world positive control: mozilla/nss `lib/freebl` (pinned `7b5f00b`, same commit as
the rest of this exploratory scan)

27 candidates, 15.2s runtime, zero crashes. Confirms the capability recognizes its own
motivating case on the REAL source (not a synthetic reconstruction of it):

**`hmacct.c::MAC`, line 184: `headerLen - mdBlockSize` feeding a `memcpy` width** --
exactly the write this session's manual audit (`moz-exploratory-scan/reports/
AUDIT_hmacct_MAC.md`) found safe today only because its one real caller happens to keep
`headerLen >= mdBlockSize`, with nothing local enforcing it. The producer's own reason
text confirms the same finding independently: `"no comparison in this function relates
headerLen and mdBlockSize"`. This is the intended target case working correctly on real
code, not just the synthetic reconstruction of it.

`MAC` also surfaced two candidates the earlier HAND audit did not chase: `mdBlockSize -
overhang` (line 185, also feeding `memcpy`) and `k - headerLen` (line 220, feeding an
array index into `data`) -- the latter's evidence is `"a relating comparison exists but
does not both dominate and control the use"`, i.e. some comparison in `MAC` DOES mention
both `k` and `headerLen`, but doesn't provably gate this particular access; worth a human
look, not chased further here (this run is a validation pass for the capability, not a
new manual audit).

The other 24 candidates span `AESKeyWrap_Winv`, `BLAKE2B_Update`/`_End`, `CMAC_Update`/
`_Finish`, `CTS_EncryptUpdate`/`_DecryptUpdate` (both previously manually audited for a
DIFFERENT concern -- destination capacity, resolved false-positive in
`AUDIT_aeskeywrap_cts.md` -- these are different subtraction sites in the same functions,
not a contradiction of that finding), `dsa_SignDigest`/`DSA_VerifyDigest`,
`gcmHash_Sync`, `mp_bmod`, `mpl_num_clear`, `makeQ2fromSeed`, `rijndael_key_expansion`
(×2 functions), `RSA_EMSAEncodePSS`/`emsa_pss_verify`, `SHA256_Update_Generic`,
`SHA512_Update` -- all `open_candidate`, all carrying `guard_evidence` (why no guard was
credited: none found, found-but-doesn't-control, wrong operand pair, or a signedness
mismatch flagged explicitly e.g. `CTS_EncryptUpdate`'s `blocksize`(unsigned) vs
`inlen`(signed)). None asserted as vulnerable -- this producer's whole posture is
flag-for-review, never assume-unsafe, same as every other `open_candidate` route in this
project.

**Zero `deterministic_complete` (safety-proven) results in this real-world run** -- every
candidate in real freebl code lacked a same-function guard the producer could prove
dominates+controls+entails. Not evidence the capability is broken (the synthetic controls
prove the credited path works); more likely evidence that this specific "safe subtraction,
locally guarded" shape is rarer in real freebl code than the guarded/unguarded call-sink
capacity shapes the base V1/V2 and cap1-3 already cover -- consistent with why this gap
existed at all (three independent hits found it via manual reading, not via an existing
producer emitting a safe verdict that happened to be wrong).

## Not re-run: full frozen-suite regression

The design doc's validation plan also called for "a regression proving zero existing
route/disposition changes anywhere else in the frozen suite (same gate-rerun pattern used
for every change this session)." This is a NEW, purely additive file
(`cap_underflow_length.py`) not imported by, and not modifying, any existing producer,
base V1/V2, `analysis_record.py`, or `cap_write_site_dedup.py` -- so there is no code path
by which it could change any existing record's route or disposition. Confirmed by
inspection (no edits to any existing file in this commit) rather than by re-running the
CAP2/CAP3/CAP4/base gates, which is the same "purely additive, so inspection suffices"
reasoning already used for cap1's original addition before its later WSD-identity
integration.

## Known gap, flagged not fixed

Same physical-write-identity gap SCANNER_IMPROVEMENT_NOTES.md item 3 named for cap1
before its WSD integration: this capability does not call `cap_write_site_dedup.py` at
all. If this capability and an existing one (e.g. cap1 or cap3) ever independently
recognize writes originating from the SAME physical site, there is no dedup path that
would catch it. Not integrated this round -- this producer's own findings are about the
SUBTRACTION's safety, a different physical node than the write itself in most of these
27 candidates (the sink call, not the write-destination expression cap1/cap3 identify),
so the overlap risk is narrower than cap1's was, but not zero for the array-index cases
(`use_kind: "array_index"`), where the identified node IS a write-adjacent index
expression. Worth a follow-up pass once real overlap is observed, same "flag now, fix
when it's proven to matter" posture as every other deferred item this session.
