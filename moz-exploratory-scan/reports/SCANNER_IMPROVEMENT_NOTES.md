# Scanner improvement notes (grounded in evidence, not the confirmatory run)

**Caveat up front**: the one-time confirmatory held-out run (`RUN_MANIFEST.json`, pinned
to scanner commit `544a606`, 258 vulnerable sites / 42 families) has its manifest
committed but `raw_sites.jsonl`/`run.log` are gitignored pending a post-run archive
commit — neither exists on this branch or anywhere on this container yet. So this is
**not** a review of that run's actual recall numbers. It's grounded instead in three
things this session directly produced or verified: the mozjpeg + nss/freebl exploratory
pilot (`PILOT_REPORT.md`), the manual `hmacct.c::MAC()` audit
(`AUDIT_hmacct_MAC.md`), and gaps already on record elsewhere in this repo's history
(cited, not re-derived). Every item below traces to one of those three sources.

## 1. A new capability class: unsigned-underflow-fed length/offset (from the hmacct.c audit)

`AUDIT_hmacct_MAC.md`'s write 2 (`firstBlock`, `hmacct.c:184`) is safe today only because
its one real caller happens to keep `headerLength >= mdBlockSize`. Nothing in the frozen
producers checks for this *shape* of bug at all: a derived quantity computed as
`unsigned_a - unsigned_b` feeding a length or offset, where `a >= b` is never locally
proven. Every current capability (cap1-4, base v1/v2) asks "is the write length ≤
destination capacity" — none of them ask "can this subtraction itself go negative first."
This is exactly the same root-cause shape the *old* TChecker corpus independently hit
twice (`CVE-2016-1950`'s `item->len += len` accumulation and bug-1418780's
`ino[0] - (moved+2)` — both filed under "integer-underflow-in-an-index/length-expression,
not yet seen as the PRIMARY cause in any corpus entry" per
`moz-scan-paired-cve-validation-round1.md` round 4). Three independent encounters
(2 old-corpus CVEs + this session's hmacct.c trace) now corroborate the same gap.
**Concrete proposal**: a producer that flags `unsigned_expr - unsigned_expr` wherever the
result feeds a `memcpy`-length, array index, or pointer-arithmetic offset, unless a
same-function guard (`if (a >= b)` / `if (a < b) return`) dominates it — same "recognize
the shape, prove-or-abstain" posture as every other capability here, not a name-based
alias.

## 2. cap3's own missing-evidence is dominated by 4 reason codes, worth breaking out

In the nss/freebl pilot, cap3 (`cap_member_pointer_walk`) recognized 17 walks — **all 17**
landed in `MISSING_EVIDENCE`, none deterministic. In mozjpeg, 68 of 68. The reason codes
(`cursor_advance_ambiguous`, `cursor_advance_non_unit`, `destination_identity_ambiguous`,
`cursor_trajectory_reset`) suggest the structural for-loop proof
(`export_for_structure.sc`) is precise but narrow — real pointer-walk loops apparently
often fail *one* of these four gates. Since `CAP3_DOMAIN_AUDIT.md`'s own adversarial
controls (shadowed decls, identical-write dedup, etc.) all pass, this isn't a soundness
bug — it's coverage. **Concrete proposal**: before building a new capability, break cap3's
own `MISSING_EVIDENCE` population out by these 4 reason codes on the actual confirmatory
corpus (once `raw_sites.jsonl` lands) and rank which single gate, if loosened
soundly, would recover the most real sites — the pilot's 100% miss rate for cap3's own
domain suggests one of the four is doing most of the rejecting, not all four equally.

## 3. cap1 (`cap_addr_indexed`) is not integrated with the frozen physical-write identity at all

Confirmed directly (not inferred) while building this session's dedup pass
(`run_moz_scan_v2.py`): `cap_addr_indexed.py` never imports `cap_write_site_dedup`, and no
other module computes a WSD identity for its output either. `CAP2_CAP3_BOUNDARY_FROZEN.md`
documents the cap2/cap3 boundary and precedence explicitly but is silent on cap1. This
means cap1's candidates cannot currently be deduplicated against cap2/cap3/base findings —
if cap1 and cap3 ever recognize the *same* physical write from different representations
(plausible: `&(base[index])` passed to a wrapper cap2 also summarizes, or a member-walk
cap3 also sees via its own addr-of-index sub-expression), it would be double-counted in
any pooled candidate report, and there is no dedup path that would catch it. In this
pilot cap1 never overlapped cap2/3 in practice (12 nss/freebl candidates, 0 mozjpeg), but
that's not the same as a proof it never will. **Concrete proposal**: give cap1 a
`WSD.physical_write_identity()` call at its one write site per record (it already resolves
a `call` object and a `dest`) and register it in the precedence tuple, ahead of or behind
`call_site_summary` per whatever the real overlap turns out to be — same pattern already
built for cap2/cap3.

## 4. `unknown_allocator_contract` recurs across the *_Resurrect family — a plausibly cheap win

8 nss + 1 mozjpeg finding, all the same shape: a `*_Resurrect` context-reuse function
writing `sizeof(*ctx)`/`sizeof(ContextType)` bytes into a pointer whose allocation-site
semantics aren't modeled (`BLAKE2B_Resurrect`, `MD2_Resurrect`, `MD5_Resurrect`,
`SHA256_Resurrect`, `SHA512_Resurrect` in this pilot alone — the naming convention alone
suggests there are more `*_Resurrect` functions elsewhere in nss following the identical
pattern). This is narrower than general interprocedural capacity propagation (the gap
`MAGMA_SCANNER_MEASUREMENT.md` and the old TChecker corpus both flag as the hardest,
highest-value capability): here the allocation and the write are usually in the *same*
translation unit, often the *same* function, just via a `sizeof(TypeName)` the frozen
producers don't fold. **Concrete proposal**: cheaper than full interprocedural capacity
propagation — a narrow extension recognizing "a pointer parameter, immediately preceded
or followed in the same function by an allocation of exactly `sizeof(SameTypeName)`
bytes for that pointer" as an established heap extent, without touching the general
unresolved-heap-pointer case.

## 5. Real macro-heavy code can blow up `normalize_c_cpp_facts_v03.py`'s reachdef pass — a pipeline robustness gap, not a modeling one

Confirmed directly this session: mozjpeg's `jchuff.c` (specifically the macro-unrolled
`encode_one_block` Huffman-bit-emission body, ~50k CPG nodes post-expansion) drove the
normalizer's reachdef pass past 4GB RSS and climbing before being killed at 240s — the
*same* function the old TChecker corpus already found pathological for a different reason
(array-size regex not folding `BUFSIZE`'s macro expansion). That earlier fix
(`_eval_const_int_expr`, a safety-restricted constant-folding evaluator) lives in the
TChecker producers, not in `normalize_c_cpp_facts_v03.py` — this pipeline doesn't share
it and re-hit a cost problem on the same function, just at a different stage
(reachdef, not array-size parsing). **Concrete proposal**: not a scanner-modeling
question — a `normalize_c_cpp_facts_v03.py` cap on reachdef worklist size per function
(the base producer already has `REACHDEF_WORKLIST_CAP_HIT` logging — mozjpeg's run
actually printed exactly that warning before the process had to be killed by wall-clock,
suggesting the existing cap doesn't actually bound wall-time/memory the way its own log
line implies it should). Worth checking whether that guard is a soft cap (logs and
continues) rather than a hard one.

## 6. The confirmatory run's own scope note is worth flagging back, not fixing

`RUN_MANIFEST.json`: *"scope: vulnerable-only recognition/recall & coverage; NOT
precision/FPR/accuracy. 101 non-vulnerable SecVulEval sites are a separate future
specificity experiment."* Not a scanner defect — but this session's own pilot did produce
real specificity signal for free (44 `DETERMINISTIC`-safe candidates across mozjpeg/nss,
all manually spot-checked as genuinely safe in the earlier findings review) that the
confirmatory run's design explicitly defers. If a specificity number is ever wanted
without a second full experiment, this pilot's 44 safe-and-verified sites (plus whatever
the eventual confirmatory run's own non-vulnerable-scope follow-up produces) could seed
it — flagging, not proposing to fold it in now, since that would blur this pilot's
explicitly non-corpus status.

---

Ranked by ratio of expected recall gain to build cost, on the evidence above: **(4) the
`*_Resurrect` allocator pattern** looks cheapest and narrowly scoped; **(2) cap3's own
missing-evidence breakdown** needs the confirmatory run's real data before it's worth
building anything (rank order can't be decided on a 100%-miss pilot sample); **(1) the
underflow-fed-length class** has the strongest corroboration (3 independent hits across
two completely different pipelines) but is the largest build; **(3) cap1 dedup
integration** is cheap and purely a correctness/bookkeeping fix, not a recall gain — worth
doing regardless of priority since it closes a silent double-counting risk; **(5)** is
infra hardening, do it whenever `normalize_c_cpp_facts_v03.py` is next touched for any
reason.
