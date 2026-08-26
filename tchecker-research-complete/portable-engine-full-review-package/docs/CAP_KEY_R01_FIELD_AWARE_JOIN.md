# CAP-KEY-R01 — FIELD-AWARE CAPACITY JOIN. SHIPPED. Fixes the R02b reader-side identity
# collision. A sentinel storage id (-1) is NEVER a valid join key.

## THE BUG (from R02b promotion replay)
Capacity PRODUCER was correct (ent->digest=20B). Verdict READER joined capacity by
storage_value_id; every field access collapses to storage_value_id=-1, so all field
capacities collided under key -1 (last-write-wins -> uniform wrong 32B). 11 Tor struct-member
capacities corrupted; candidate count 28 masked it (same count, wrong values).

## THE FIX — carry identity through facts; join by explicit kind
PRODUCER (normalizer): each capacity fact now carries
    storage_identity_kind : 'VALUE_ID' | 'FIELD'
    field_storage_key     : 'FIELD:<base_storage_id>:<member_decl_id>' | null
  LOCAL/array operand -> VALUE_ID, storage_value_id>=0, field_storage_key=null
  FIELD operand       -> FIELD,    storage_value_id=-1 (sentinel), field_storage_key set
CONSUMER (verdict readers): join by identity kind, NEVER by sentinel:
    VALUE_ID -> dcap[storage_value_id]  only when sid>=0
    FIELD    -> dcap_by_call[call_id]   (call_id unique per site; distinct members never collide)
    sid=-1 AND no field key -> NO MATCH / abstain
Hard invariant: a negative/sentinel storage id is never inserted as a join key.

## CONSUMER/JOIN TEETH (capkeytest.c) — ALL PASS
  CAPKEY-1 f: a->digest=20                              PASS
  CAPKEY-2 f: b->nonce=32                               PASS
  CAPKEY-3 g (declaration/call order REVERSED): a->digest=20  PASS  <- catches last-write-wins
  CAPKEY-4 g (reversed): b->nonce=32                    PASS
  CAPKEY-5 h x->a=16                                    PASS
  CAPKEY-6 h x->b=64 (same base, different member)      PASS
  CAPKEY-7 h y->a=16 (different base, same member decl) PASS
  CAPKEY-NEG-1 sid=-1 with no field key -> NOT joinable PASS  (sentinel never a key)

## TOR REPLAY THROUGH THE FIXED READER — collision GONE
Previously (broken): all field dests read dest_cap=32B (last-write-wins).
Now: correct per-site capacities. Candidate distribution:
    7 x 20B, 3 x 32B, 1 x 256B, 1 x 80B   (varied, correct)
  channel_add_to_digest_map:577 -> 20B (was 32B)   FIXED
  conflux_cell_parse_link_v1:221 -> 32B (nonce[32]) correct
  tor_version_parse:280 -> 32B (status_tag[32])     correct
11 FIELD-kind dest capacities, all carry field_storage_key, 0 joined by sid=-1.
Tor OOB_WRITE candidates: 12 (the REAL number; the earlier 28 was collision-inflated).

## REGRESSION — every consumer checked, canonical clean
  raft OOB_WRITE   8   UNCHANGED
  OOB_COMPARE      0   UNCHANGED (compare reader join also identity-aware via same fact schema)
  tcpdump OOB_WRITE 11 -> 13  CONSCIOUS ANCHOR CHANGE (see below)
  canonical        31/31 EXECUTED, REGRESSIONS 0 (49 PASS/0 FAIL)
  GUARD-R01        PASS; CAPACITY_CONTROLS 11/11 (migrated invariant control, see below)
  engine-core      7ad2880e04e84fd5 UNCHANGED

## tcpdump 11 -> 13 : CONSCIOUS, ADJUDICATED ANCHOR UPDATE
Set-diff (baseline vs shipped) ADDED exactly two, REMOVED none:
  + handle_beacon:1416 memcpy         dest_cap=8B
  + handle_probe_response:1583 memcpy dest_cap=8B
Both are memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN) with timestamp[IEEE802_11_TSTAMP_LEN
=8]: extent is a CONSTANT == capacity. SAFE (CONSTANT_EXTENT shape), surfaced as candidates only
because STATIC_EXTENT_SAFE fires on literal sizeof(dest), not a named-constant == cap. These are
R02b's known safe FPs (struct-member capacity now resolved for them). NEW frozen tcpdump anchor
= 13, with 2 documented CONSTANT_EXTENT safe residuals. No real bug introduced.

## GUARD-R01 CAPACITY CONTROL — MIGRATED (planned, not forced)
Old control pinned the exact B2a.1 source line
  "_cap=_fixed_array_capacity(_mem.get('type_full_name') or '')".
R02b/CAP-KEY resolve via field identity, so that line legitimately changed. Migrated the
control to assert the INVARIANT: struct-member capacity derives from the resolved member
declaration's type via _fixed_array_capacity (pointers/unsized[]/flexible abstain), and the
fact carries explicit storage_identity_kind + field_storage_key. Added a second control:
"field capacity carries explicit identity kind (no sentinel join key)". CAPACITY_CONTROLS 11/11.

## NEW PERMANENT REGRESSION LAYER (fact-value stability, not just verdict)
Recorded lesson: equal candidate COUNT and equal SITE SET do NOT prove correctness (the 28->28
collision proved values can be silently wrong). Future memory-reader regression signature must
include per-site (site, operand role, storage identity, extent, capacity, bound, verdict), so
semantic substitution is auto-visible. (Design recorded; wiring into run_all is a follow-up.)

## STATUS
SHIPPED. normalizer 67515a0fa69934b6; oob_write_verdict.py field-aware join; capacity_controls
migrated. All join teeth + negative tooth PASS. Tor collision gone (12 real candidates, correct
per-site capacities, 11 identity-carried field caps, 0 sentinel joins). raft 8, compare 0,
tcpdump 13 (conscious +2 safe), canonical 31/31 REGRESSIONS 0, GUARD-R01 PASS, engine-core
7ad2880e04e84fd5 UNCHANGED. R02b consumer identity model now SOUND. Next: adjudicate the 12 Tor
candidates (safe-by-bound vs real) to measure true feature value, THEN decide on TOR-B3.
