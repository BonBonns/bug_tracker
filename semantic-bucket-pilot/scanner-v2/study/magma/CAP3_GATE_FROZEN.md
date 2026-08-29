# Capability 3 — advancing-pointer struct-member walks (FROZEN gate)

Runnable gate `gate_capability_3.py` -> `CAP3_GATE=PASS`. Frontend joern-c2cpg v4.0.608.
No model calls. Magma/PNG003 used as DEVELOPMENT evidence only; the frozen held-out corpus
is NOT referenced (enforced by grep in the gate). Implementation: `cap_member_pointer_walk.py`.

## Scope (exactly the audited remainder)

Owns ONLY advancing-pointer struct/union MEMBER writes: `p->field = x` / `p.field = x`
with the pointer advanced separately (`p++` / `++p` / `p += 1`). This is the PNG003
palette shape the frozen cursor producer misses (CAP3_DOMAIN_AUDIT.md). It does NOT claim
general non-byte aggregate writes (e.g. `*p++ = struct_value`) — that would need its own
model and controls. Additive: emits `attribution="direct"` records through
`cap_write_site_dedup`, where the frozen precedence keeps the cursor producer canonical on
any site it already recognizes (cursor_producer > direct > call_site_summary).

## Method (two-part, all from frozen facts)

- Pointer declaration resolved via Joern reference-target (`ref_target_ids`), never by name.
- Capacity bound ONLY from an independently-established fixed-array or literal-count
  allocation extent (element count); unknown struct-field / parameter / alias / realloc /
  symbolic-allocation capacity stays UNRESOLVED (abstain), never assumed.
- Cursor trajectory examined explicitly: single base binding; single UNIT advance; the
  advance proven per-iteration only when it is the for-UPDATE (on the loop-header line);
  loop counter + bound; write-before-advance (no one-past); no reset; no alias conflict.
- All member writes through ONE cursor (PNG003 red/green/blue) are ONE operation with ONE
  capacity obligation and ONE proof family — never three independent families.

## Controls (cap_member_pointer_walk_test.py, ALL PASS)

Positive: `mw_open` (symbolic unguarded) -> open_candidate / write_count_bound_not_established,
ONE op over 3 member writes, ONE family_id, capacity 256 established from the static array.
Resolved: `mw_guarded` (visible clamp) and `mw_fits` (literal 100<=256) -> deterministic_complete;
`mw_over` (literal 300>256) -> proven_oversized.
Adversarial abstentions, each a distinct trajectory/capacity failure:
`mw_cond` conditional increment -> cursor_advance_not_proven_per_iteration;
`mw_multi` multiple increments -> cursor_advance_ambiguous;
`mw_reset` pointer reset -> cursor_trajectory_reset;
`mw_alias` alias conflict -> destination_identity_ambiguous;
`mw_onepast` body advance before write -> cursor_one_past_write;
`mw_param` parameter/unknown-lifetime base -> capacity_of_base_unresolved.
Early exit `mw_break` -> open_candidate (count is a sound upper bound, never a false safe);
symbolic/negative bound never yields deterministic_complete.
Negatives (outside the domain -> NO cap3 op): `mw_single` non-advancing single member
write; `mw_byte` byte `*p++` deref (cursor-producer domain). 0 ops on a bare-memcpy file.
PNG003 extracted dev body -> ONE open_candidate over 3 writes, capacity 256.

## Reported metrics (development corpus)

1. **Writes recognized** — member writes recognized as walks: mw_open 3, PNG003 3, plus
   1 each for the guarded/literal/adversarial cases; on real NSS lib/util, 19 member-walk
   operations recognized.
2. **Capacity facts established** — from static arrays only: mw_open/guarded/fits/over and
   PNG003 all bind 256 (png_color[256] / rgb[256]); parameter base (mw_param) and every
   real-NSS site remained UNRESOLVED (not assumed).
3. **Relationships resolved** — mw_guarded (clamp -> bounded) and mw_fits (100<=256) ->
   deterministic_complete; mw_over (300>256) -> proven_oversized.
4. **Correct abstentions** — 6 distinct reasons (advance-not-proven, advance-ambiguous,
   trajectory-reset, identity-ambiguous, one-past, capacity-unresolved); on real NSS
   lib/util ALL 19 member-walk sites abstained (no false candidates).
5. **Existing verdicts changed outside the new domain — ZERO.** cap3 is a separate,
   additive module: ANALYSIS_RECORD_R01 stays 53/53; cap3 emits nothing on the cursor-domain
   deref fixtures (a1/a2/a4/a5) or on byte `*p++`; its member-write sites are disjoint from
   the frozen cursor producer's recognized sites; cap2 gate unaffected (CAP2_GATE=PASS).

## Frozen

Held-out measurement remains deferred: no SecVulEval/Big-Vul/ARVO/pooled result inspected.
Capability 4 (external decoder contracts) is next; it must not move this gate.
