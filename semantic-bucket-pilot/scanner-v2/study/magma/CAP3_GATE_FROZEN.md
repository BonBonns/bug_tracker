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

## Method (all from frozen facts + a separate CPG/AST query)

- Pointer declaration resolved via Joern reference-target (`ref_target_ids`), never by name.
- Capacity bound ONLY from an independently-established fixed-array or literal-count
  allocation extent (element count); unknown struct-field / parameter / alias / realloc /
  symbolic-allocation capacity stays UNRESOLVED (abstain), never assumed.
- **Cursor trajectory proven STRUCTURALLY via the CPG/AST — NOT by source-line coincidence**
  (the earlier line heuristic was unsound on multiline headers, body increments written on
  the header line, macros, and shared lines). `export_for_structure.sc` runs as a SEPARATE
  analysis on the scan's `cpg.bin` (it does not modify the frozen exporter or the producers'
  `cpp.json`) and emits, per FOR loop, the CPG node ids of its condition / update / body AST
  subtrees. Capability 3 then proves: (1) the increment node is in a FOR's UPDATE component;
  (2) all member writes are in that same FOR's BODY; (3) write-before-update follows from the
  for-loop's structured semantics (UPDATE executes after BODY each iteration); the loop bound
  is taken from that FOR's CONDITION. It FAILS CLOSED (abstains) when the control-structure
  facts are unavailable, or the increment is a body/while/conditional increment, or the writes
  are not in the matching body. Base binding, single unit advance, no reset, no alias conflict
  are checked as before.
- All member writes through ONE cursor (PNG003 red/green/blue) are ONE operation with ONE
  capacity obligation and ONE proof family — but the THREE physical write sites are PRESERVED
  as three distinct verifiable identities (`member_writes`, `member_write_nodes`), not erased.
- **Guard/symbolic bound:** a safety claim on a symbolic bound would require rigorously
  proving a guard that dominates the loop, constrains this exact bound declaration, has the
  correct polarity, and is not invalidated before/during the loop — NOT attempted. So only a
  LITERAL bound yields deterministic_complete / proven_oversized; every SYMBOLIC bound
  (guarded or not) is a conservative open_candidate, never a false safe. For signed `num` the
  effective count is `max(0, num)`: a negative value means zero iterations (does not overflow)
  but does not RESOLVE the relation, so signedness alone is not "unresolved" — it stays an
  open-candidate flag; a bound that is an arithmetic expression (possible conversion/overflow)
  is flagged `symbolic_expr`.

## Controls (cap_member_pointer_walk_test.py, ALL PASS)

Positive: `mw_open` (symbolic unguarded) -> open_candidate / write_count_bound_not_established,
ONE op over 3 member writes (3 DISTINCT physical identities), ONE family_id, capacity 256
established from the static array, structural proof (advance in for-UPDATE, writes in for-BODY).
AST regressions (where the old line heuristic failed): `mw_multiline` (multiline for-header)
-> recognized (open_candidate); `mw_sameline` (body increment written on the header line) ->
abstain cursor_advance_in_loop_body_not_update.
Resolved (LITERAL only, sound without a guard proof): `mw_fits` (100<=256) ->
deterministic_complete; `mw_over` (300>256) -> proven_oversized. `mw_guarded` (symbolic,
visible clamp) -> open_candidate (no unproven safe claim).
Adversarial abstentions, each a distinct trajectory/capacity failure:
`mw_cond` conditional increment -> cursor_advance_in_loop_body_not_update;
`mw_multi` multiple increments -> cursor_advance_ambiguous;
`mw_reset` pointer reset -> cursor_trajectory_reset;
`mw_alias` alias conflict -> destination_identity_ambiguous;
`mw_onepast` body advance before write -> cursor_advance_in_loop_body_not_update (one-past is
subsumed: a for-UPDATE increment can never one-past the member write by structured semantics,
and any body increment abstains);
`mw_param` parameter/unknown-lifetime base -> capacity_of_base_unresolved.
Early exit `mw_break` -> open_candidate (count is a sound upper bound, never a false safe);
symbolic/signed bound never yields deterministic_complete.
FAIL CLOSED: with the control-structure facts withheld, `mw_open` abstains
(for_structure_unavailable) -- no line-heuristic fallback.
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
4. **Correct abstentions** — distinct reasons (advance-in-loop-body-not-update,
   advance-ambiguous, trajectory-reset, identity-ambiguous, capacity-unresolved,
   for-structure-unavailable); on real NSS lib/util ALL 19 member-walk sites abstained.
5. **No unsupported promotions on NSS** — on real NSS lib/util, cap3 made ZERO promotions
   (0 open_candidate / deterministic / oversized; all 19 abstained). NOTE: without outcome
   labels this cannot establish a false-candidate *rate*; the claim is only that cap3 issued
   no verdict beyond an established capacity + a structurally proven trajectory (it never
   promoted on unresolved capacity or an unproven trajectory).
6. **Existing verdicts changed outside the new domain — ZERO.** cap3 is a separate, additive
   module: ANALYSIS_RECORD_R01 stays 53/53; cap3 emits nothing on the cursor-domain deref
   fixtures (a1/a2/a4/a5) or on byte `*p++`; its member-write sites are disjoint from the
   frozen cursor producer's recognized sites; cap2 gate unaffected (CAP2_GATE=PASS). The
   shared write-identity module was extended to recognize member-write targets (so cap3's
   physical sites resolve); `*`-prefixed pointer-WALK detection is unchanged, and the cap2 /
   identity / domain-audit gates all still pass.

## Frozen

Held-out measurement remains deferred: no SecVulEval/Big-Vul/ARVO/pooled result inspected.
Capability 4 (external decoder contracts) is next; it must not move this gate.
