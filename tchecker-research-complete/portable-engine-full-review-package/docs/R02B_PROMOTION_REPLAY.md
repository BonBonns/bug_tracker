# R02b PROMOTION REPLAY on the resolved 75% — RESULT: PROMOTION BLOCKED by a real reader-side
# identity-collision defect. R02b NOT shipped. Frozen state intact. Defect precisely located.

## PROTOCOL RUN (best-available Tor directory facts, capacity consumes frozen FieldStorageIdentity)
Built core/or directory CPG (3.1MB), exported, normalized with R02b reference patch.

## GATE RESULTS
  FIELD-ID teeth (FID-1,2,4,8)            PASS
  CAP-FID teeth (1-5, incl pointer abstain) PASS
  flexible-array abstention (9 unsized, 0 caps emitted) PASS
  R02a/R02a.1 identities unchanged (3512==3512, identical set) PASS
  Tor capacity classification:
    FIELD_ID_PRESENT        53
    CAPACITY_EMITTED        19   <- real non-zero Tor capacity (overturns flat-scan "0")
    POINTER_MEMBER           6   (abstain)
    UNKNOWN_ARRAY_DIMENSION 16   (header-context abstain)
    UNKNOWN_ELEMENT_WIDTH   12
  struct-member dest capacities emitted:   11 (digest[20], identity_digest[20], nonce[32],
                                              node_id[20], status_tag[32], ...)

## THE BLOCKING DEFECT (found by adjudicating capacities, not counts)
The 11 struct-member capacity FACTS are CORRECT (channel_add_to_digest_map:577 ent->digest =
20B uint8_t[20], verified). BUT the verdict reader (oob_write_verdict.py) keys capacity by
storage_value_id:
    dcap = { f['storage_value_id'] : f for f in dest_capacities }
and every field-access dest has storage_value_id = -1 (the collapsed field id). So ALL 11
struct-member capacities collide under key -1 and overwrite each other; last-write-wins yields
a UNIFORM WRONG dest_cap=32B for every struct-member site (e.g. ent->digest, truly 20B, reads
as 32B). Distinct real capacities {20,32} collapse to one.
=> R02b emits correct capacity but the READER cannot distinguish field-access dests by
storage_value_id=-1. This is the SAME storage-identity collision the FIELD-ID arc exists to
fix, resurfacing on the CONSUMPTION side: the capacity emission was taught to use the
composite key, but the VERDICT READER still keys by the collapsed sid.

## WHY THE COUNT HID IT (discipline note)
Baseline (R02a.1, which ALREADY has B2a.1 name-based struct caps) = 28 OOB_WRITE candidates;
R02b = 28. Site-level set-diff showed 0 added / 0 removed. The count and the site set were
UNCHANGED, yet the per-site capacity VALUES were silently wrong (cross-contaminated). Only
adjudicating the actual capacity numbers (not the candidate membership) exposed it. This is a
second instance of the invariant: equal counts / equal site-sets do NOT prove correctness.

## VERDICT: R02b FAILS PROMOTION (correctly), NOT SHIPPED
create_cell_init:110 is NOT used as a success/failure criterion (per plan: it is a
frontend-context + interprocedural abstention case, a poor validation anchor). The failure
here is independent of it: it is the reader keying by sid=-1.

## WHAT R02b ACTUALLY NEEDS (before any re-attempt) — now precisely scoped
1. CAPACITY KEYING MIGRATION: the dest/src/cmp capacity facts must carry the FieldStorageIdentity
   composite_key, and the verdict readers (oob_write/read/compare) must match capacity to a
   field-access operand by that composite key, NOT by storage_value_id when sid==-1. This is a
   READER change (and a fact-keying change), i.e. touches the verdict tools — NOT just the
   normalizer. It is the real, now-identified unit of work.
2. GUARD-R01 capacity-control migration (still owed): assert the INVARIANT (capacity only when
   proven member identity + fixed-array declared type + concrete extent; abstain for pointer /
   unsized [] / flexible array / unresolved identity) instead of the pinned B2a.1 source line.
3. Re-adjudicate every Tor + tcpdump + raft delta AFTER the keying fix, since correct
   per-site capacities may change candidate membership (currently masked).

## STATUS
R02b PROMOTION BLOCKED. Real defect: verdict reader keys field-access capacity by
storage_value_id=-1 -> 11 struct-member capacities collide (uniform wrong 32B). R02b emits
correct facts but is unusable until the reader keys by composite identity. NOT SHIPPED.
Engine frozen at R02a.1 (9c535347e330c483), core 7ad2880e04e84fd5, tcpdump 11, raft 8,
canonical 31/31 — UNCHANGED. Positive finding preserved: real Tor capacity yield is 19
(non-zero), confirming the feature has value once the keying defect is fixed. Next unit of
work is the capacity-keying migration (reader + fact key), then re-run this exact protocol.
