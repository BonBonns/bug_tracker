# TOR-CAND-R01 — adjudication of the 12 correctly-keyed Tor OOB_WRITE candidates.
# OBSERVATIONAL ONLY. No code, no gates, no TOR-B3. Question: why does each remain?
# Semantic VALUES verified (not just verdicts): all emitted capacities == expected. No corruption.

## THE 12 CANDIDATES (site | dest | extent | cap | class)
1. channel_add_to_digest_map:577  memcpy(ent->digest, chan->identity_digest, DIGEST_LEN)
     cap=20 extent=DIGEST_LEN=20  -> extent==capacity  SAFE_CONSTANT_EQUAL_CAPACITY
2. channel_clear_identity_digest:1325 memset(chan->identity_digest,0,sizeof(chan->identity_digest))
     cap=20 extent=sizeof(dest)   -> SAFE_OTHER_DEMONSTRATED (sizeof-of-exact-dest)
3. channel_set_identity_digest:1370 memcpy(chan->identity_digest,_,sizeof(chan->identity_digest))
     cap=20 extent=sizeof(dest)   -> SAFE_OTHER_DEMONSTRATED
4. channel_set_identity_digest:1374 memset(chan->identity_digest,0,sizeof(chan->identity_digest))
     cap=20 extent=sizeof(dest)   -> SAFE_OTHER_DEMONSTRATED
5. channel_clear_remote_end:1413 memset(chan->identity_digest,0,sizeof(chan->identity_digest))
     cap=20 extent=sizeof(dest)   -> SAFE_OTHER_DEMONSTRATED
6. conflux_cell_new_link:278  memcpy(link->nonce, nonce, sizeof(link->nonce))
     cap=32 extent=sizeof(dest)   -> SAFE_OTHER_DEMONSTRATED
7. or_connect_failure_init:1269 memcpy(ocf->identity_digest,_,sizeof(ocf->identity_digest))
     cap=20 extent=sizeof(dest)   -> SAFE_OTHER_DEMONSTRATED
8. extend_info_new:43  memcpy(info->identity_digest, rsa_id_digest, DIGEST_LEN)
     cap=20 extent=DIGEST_LEN=20  -> SAFE_CONSTANT_EQUAL_CAPACITY
9. conflux_cell_parse_link_v1:221 memcpy(link->nonce, getconstarray_nonce(payload),
     getlen_nonce(payload))  cap=32 extent=runtime trunnel getlen -> INTERPROC/RUNTIME extent
     -> EXTENT_UNRESOLVED (parser-runtime length; capacity known, extent not statically bounded)
10. tor_version_parse:280 memcpy(out->status_tag, cp, eos-cp)
     cap=32 extent=(eos-cp) pointer-diff  -> EXTENT_UNRESOLVED (runtime pointer arithmetic;
     needs a proven eos-cp <= 32 bound; not present locally)
11. circuit_change_purpose:3181 strncpy(old_purpose_desc, _, 80-1)  cap=80 (LOCAL array, key=None)
     extent=80-1=79 < 80  -> SAFE_CONSTANT_EQUAL_CAPACITY (pre-existing baseline candidate, not
     R02b-new; strncpy n<cap)
12. connection_ap_handshake_socks_reply:3958 memset(buf,0,SOCKS4_NETWORK_LEN) cap=256 (LOCAL,
     key=None) extent=SOCKS4_NETWORK_LEN=8 << 256 -> SAFE_CONSTANT_EQUAL_CAPACITY (pre-existing)

## TAXONOMY DISTRIBUTION (of 12)
  SAFE_OTHER_DEMONSTRATED (extent = sizeof(EXACT dest field)):     6   (#2,3,4,5,6,7)
  SAFE_CONSTANT_EQUAL_CAPACITY (extent = const <= cap):            4   (#1,8,11,12)
  EXTENT_UNRESOLVED (runtime length: getlen / pointer-diff):       2   (#9,10)
  INTERPROC_GUARD_REQUIRED:                                        0
  ACTUAL_UNSAFE_CANDIDATE:                                         0
=> 10 of 12 are SAFE with evidence Fable ALREADY HAS but the reader misses; 2 have runtime
extents (not interprocedural-guard, but unresolved-length); 0 need caller-guard transfer;
0 genuinely unsafe.

## THE DOMINANT RESIDUAL IS A READER GAP, NOT A MISSING CAPABILITY
10/12 are safe by evidence present at the site:
  - 6 use extent = sizeof(chan->identity_digest) i.e. sizeof of the EXACT dest field. The
    existing is_static_extent_safe handles sizeof(local) but NOT sizeof(obj->member) (the
    field-access form). Extending STATIC_EXTENT_SAFE to field-access dests (dest fieldkey ==
    sizeof-operand fieldkey) would suppress all 6 SOUNDLY — same-storage proven by identity,
    the exact discipline CAP-KEY-R01 just established.
  - 4 are const <= cap (DIGEST_LEN==cap; strncpy n=cap-1; SOCKS4_NETWORK_LEN<<cap). A
    CONSTANT_EXTENT_LE_CAPACITY suppressor (const extent <= resolved cap) would handle these,
    BUT this was cross-corpus VETOED earlier (tcpdump +9 FPs) — so it stays unpromoted; these
    remain honest candidates, not bugs.

## ROADMAP IMPLICATION (this is the measurement that chooses next work)
Result shape:
  12 = 6 sizeof(field)-safe + 4 const-safe + 2 runtime-extent + 0 interproc + 0 unsafe
=> TOR-B3 (interprocedural caller-guard transfer) is NOT indicated by this corpus: ZERO of the
   12 need it. The memorable create_cell_init:110 case is NOT among these 12 (its onionskin
   dimension is header-context-unresolved, so it never became a keyed candidate here).
=> The HIGH-YIELD next capability is a narrow reader improvement:
   FIELD_SIZEOF_SAFE — STATIC_EXTENT_SAFE for field-access dests where extent == sizeof(same
   field storage key). Sound (identity-proven same storage), suppresses 6/12 immediately, and
   is analogous to the already-promoted sizeof(local) case. NOT an interprocedural expansion.
   The 2 EXTENT_UNRESOLVED (trunnel getlen, pointer-diff) are separate runtime-length problems;
   neither is caller-guard transfer.

## SEMANTIC-VALUE VERIFICATION (per the new discipline)
For all 6 FIELD candidates: emitted capacity == expected declared capacity (ent->digest 20==20,
chan->identity_digest 20==20, link->nonce 32==32, ocf->identity_digest 20==20,
info->identity_digest 20==20, out->status_tag 32==32). 0 mismatches. Identity keys distinct per
storage. No silent cross-fact corruption. call_id used ONLY as the mechanical retrieval handle
for the fact at a site; the SEMANTIC storage identity remains the FieldStorageIdentity composite
key (verified distinct per member). The two are kept conceptually separate.

## STATUS
Observational milestone complete. 12 candidates adjudicated: 10 safe-by-present-evidence
(6 sizeof-field, 4 const), 2 runtime-extent-unresolved, 0 interprocedural, 0 unsafe. No engine
change. Engine frozen at CAP-KEY-R01 (normalizer 67515a0fa69934b6), core 7ad2880e04e84fd5,
tcpdump 13, raft 8, compare 0, canonical 31/31. NEXT (measured, not chosen by anecdote):
FIELD_SIZEOF_SAFE reader suppressor for sizeof(field)==dest-field. TOR-B3 is NOT next: this
corpus shows zero interprocedural-guard-required candidates.
