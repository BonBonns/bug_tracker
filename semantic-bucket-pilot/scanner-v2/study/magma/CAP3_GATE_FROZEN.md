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
  is flagged `symbolic_expr`. `max(0, num)` applies ONLY to the canonical signed `i=0; i<num;
  i++` form — never assumed for any other init/operator/step.
- **The ITERATION COUNT is proven, not the bound token.** A literal bound token is NOT the
  write count. A verdict (deterministic_complete / proven_oversized) is issued only when ALL
  of these are literal and structurally established: (1) the counter's initial value from the
  for-INIT; (2) the comparison operator (`<`, `<=`, `>`, `>=`, `!=`) from the for-CONDITION;
  (3) a single unit/literal counter step and its DIRECTION from the for-UPDATE (`i++`→+1,
  `i--`→−1, `i+=k`→+k, `i-=k`→−k); (4) the counter is NOT modified in the BODY; (5) the
  cursor's STARTING OFFSET from its base binding (`array`→0, `array+k`→k, `&array[k]`→k,
  literal k only). In-bounds iff `start_offset + count <= capacity`. So the count is **257**
  for `i=0; i<=256` (oversized, not 256); **256** for `i=1; i<=256`; **255** for `i=1; i<256`;
  **128** for `i+=2` over `[0,256)`. Any of (1)–(5) not literally established → conservative
  `open_candidate` with a specific `bound_shape` (`counter_modified_in_body`,
  `symbolic_expr`/`symbolic_signed`/`symbolic_unsigned`, `cursor_offset_unresolved`,
  `counter_step_ambiguous`, `counter_init_unresolved`) — never a false safe.
- **CLOSED-FORM count, no analysis-time DoS.** The trip count is computed by O(1) closed-form
  arithmetic (`_trip_count`), NOT by iterating the loop — a literal bound of two billion is
  resolved instantly, never simulated. Cases the closed form does not resolve return
  `trip_count_indeterminate` (open); a loop that does not terminate over the integers returns
  `nonterminating` → proven_oversized (it writes without bound, exceeding any finite capacity).
- **C INTEGER SEMANTICS gate.** The ideal-integer count is trustworthy only if stepping the
  counter of its DECLARED type from `i0` to the exit value `E = i0 + count·step` (the first
  value failing the condition) cannot overflow/wrap, and the bound is representable in that
  type (no signed↔unsigned conversion surprise). `_counter_range` resolves the counter's C
  type to `[min,max]` (unsigned/width from `type_full_name`); a deterministic promotion
  requires `i0`, `E`, and the bound all within range. If the type is unknown or any endpoint is
  exceeded (signed overflow at the boundary, unsigned decrement wrapping past 0, …), no-wrap is
  unproven → conservative `open_candidate` (`counter_overflow_unproven`), never a false safe.
  `max(0, num)` applies ONLY to the canonical signed `i=0; i<num; i++` form.
- **Hash-bound CPG with semantic witnesses (two-file binding manifest).** Node ids are
  meaningful only within one CPG generation, and Capability 3 combines the normalized facts
  (`cpp.json`) with a separate query on `cpg.bin` (`export_for_structure.sc`). Hashing
  `cpg.bin` + checking node witnesses establishes strong cross-artifact CONSISTENCY but does
  not by itself bind the complete `cpp.json`; so the binding manifest (`for_structure.json`)
  stores the SHA-256 of BOTH files, and at analysis time cap3 recomputes BOTH the current
  `cpp.json` and the current `cpg.bin` and requires an exact match against the manifest, AND
  re-checks per-FOR **semantic witnesses** (the condition node's id + code) against
  `cpp.json`'s calls (catching same-manifest-hash-but-wrong-generation node id reuse). The
  manifest is regenerated if the `cpg.bin` sha changes (stale-artifact protection). Any failure
  → cap3 **fails closed** (`for_structure_cpp_cpg_mismatch`), never trusting cross-generation
  node ids.
- **Fail-closed dedup uses a monotonic per-run index, never `id(object)`.** Unverifiable
  records (source position or declaration ordinal unresolvable) all collapse to the same
  `identity_key` (`("UNVERIFIABLE", node_or_None)`), so identity alone would merge them. Dedup
  routes each to a separate never-merged op carrying an explicit monotonically-assigned
  `unverifiable_index` (from `enumerate`). It is NOT a semantic identity — it only guarantees
  "never merge." `id(record)` is gone everywhere (object-address reuse across short-lived temps
  is unsound).

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
ITERATION-COUNT controls (the bound token is not the write count — each simulated):
`mw_le256` (`i=0; i<=256`) -> proven_oversized at **257** writes (NOT safe though the token
256 equals capacity); `mw_init1` (`i=1; i<=256`) -> deterministic_complete at **256**;
`mw_dec` (`i=256; i>0; i--`) -> deterministic_complete at **256** (decrementing, `>` op);
`mw_step2` (`i=0; i<256; i+=2`) -> deterministic_complete at **128** (literal step, not 256);
`mw_bodymod` (counter mutated in body) -> open_candidate `counter_modified_in_body`;
`mw_offset` (`cursor = array + 100`, 200 writes) -> proven_oversized (reaches index 299 >=
256; the start offset is counted, not dropped).
NO-DoS / C-SEMANTICS controls: `mw_huge` (`i<2000000000`) -> proven_oversized computed by O(1)
closed form (the test returns instantly, never iterating 2e9 times); `mw_ovf`
(`i=2147483645; i<=INT_MAX; i++`) -> open_candidate `counter_overflow_unproven` (only 3 body
runs, but the final `i++` overflows signed `int` — not promoted to a false fit); `mw_wrap`
(`unsigned i=300; i>=0; i--`) -> open_candidate `counter_overflow_unproven` (decrement wraps
past 0; the ideal count is not the real one).
BINDING controls (two-file manifest + witnesses): a tampered `for_structure` witness (code no
longer matching `cpp.json`) -> fail closed `for_structure_cpp_cpg_mismatch`; a `cpp.json` hash
not matching the manifest -> fail closed even with witnesses intact (the check witnesses alone
cannot make). Cross-generation node ids are never trusted.
DEDUP control: two unverifiable records collapse to the same `identity_key` yet dedup keeps
them as two distinct never-merged ops with monotonic `unverifiable_index` 0/1 (no `id()`).
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
