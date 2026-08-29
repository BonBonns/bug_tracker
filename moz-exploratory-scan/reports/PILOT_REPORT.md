# Bounded pilot — mozilla/nss + mozilla/mozjpeg (exploratory, not held-out)

Ran the FROZEN scanner-v2 producers — base v1/v2 write-capacity comparison + capabilities
1-4 (`cap_addr_indexed`, `cap_wrapper_summary`, `cap_member_pointer_walk`,
`cap_counted_loop_writer`) — **unmodified**, imported read-only from the definitive branch
(`claude/previous-conversation-context-6gr99h` @ `8b77705`), against current heads of two
Mozilla C/C++ projects. This is vulnerability-discovery/portability work, run alongside
Capability 4 development; it does **not** touch, extend, or reference the frozen held-out
corpus (258 vulnerable sites / 42 families) and makes no accuracy/generalization claim. No
CVE list was consulted to select or promote any finding below — every candidate the
producers emitted on the scanned scope is reported.

## Toolchain

- joern-cli / c2cpg **v4.0.608** (`/tmp/joern-cli`) — same pin as `TOOLCHAIN_FROZEN.md` on
  the definitive branch.
- Frontend: `export_c_cpp_facts_v03.sc` → `normalize_c_cpp_facts_v03.py` (both read
  unmodified from `tchecker-research-complete/.../tests/gates/cpp-r06/frontend/`).
- Driver: `run_moz_scan.py` (this repo, `moz-exploratory-scan/commands/`) — imports the
  five producer modules and calls their public `analyze_*` entry points as-is; it changes
  no producer/capability/rule/route. It adds only reporting glue: a disposition→bucket
  classifier built from each producer's *own* existing vocabulary (`disposition`/`route`
  for cap1-4 and v2-refined records; `analysis_status`/`reason_code`/`uncertainty_bucket`
  for v1-passthrough records), and a best-effort `(file, function, line, dest)` identity
  string per finding (see caveat below).

## Scope pinning

| Repo | URL | Pinned commit | Clone |
|---|---|---|---|
| mozilla/nss | github.com/mozilla/nss | `7b5f00bfd3835fee76be428c55e60cdb3366182c` | `--depth 1` |
| mozilla/mozjpeg | github.com/mozilla/mozjpeg | `08265790774cd0714832c9e675522acbe5581437` | `--depth 1` |

Each pinned twice — `git ls-remote <url> HEAD` before cloning, `git rev-parse HEAD` after —
and the two agree in both cases (see `sources_pin/*.md`).

## Bounded pilot (this round)

- **mozjpeg — full source tree, minus `jchuff.c`.** `jchuff.c` was excluded from the
  c2cpg source scan (`--exclude jchuff.c`), not silently dropped after the fact: its
  Huffman encoder body is the same heavily macro-unrolled function documented in
  `moz-scan-paired-cve-validation-round1.md` round 2 (`encode_one_block`, ~50k CPG nodes
  after macro expansion). Re-encountered here as a **normalize-time cost blowup**, not a
  parse failure this time — the earlier session's fix was a capacity-constant-folding
  evaluator in the TChecker producers, which this scanner-v2 pipeline does not share;
  `normalize_c_cpp_facts_v03.py`'s reachdef pass on that one function grew unbounded
  (>4GB RSS and climbing before being killed at the 240s mark). **This is a real, reproduced
  scanner-v2 coverage/performance gap on macro-heavy real code, recorded here, not patched**
  (patching it now would be tuning the scanner on a file this same session is about to
  scan with it — exactly the training-on-test problem the definitive branch's own rules
  forbid). Every other file in the tree parsed and normalized cleanly (build-configured via
  `cmake -B build_cfg`, no full compile needed — c2cpg only needs the generated headers).
- **nss — `lib/freebl/` only** (123 `.c` files: the crypto-primitive tree; matches the area
  prior sessions' `/tmp/nss-crypto-scan` work also found tractable). `--include`d
  `lib/util`, `lib/freebl/mpi`, `lib/freebl/ecl` for header resolution via
  `--with-include-auto-discovery`; no NSPR/build.sh build was run (parse-only, not link).
  The rest of `nss/lib/` (ssl, softoken, pk11wrap, …) is **not yet scanned** — see
  "Scoping the complete feasible source scope" below.

## Results

| Target | Candidates | DETERMINISTIC | OPEN_RELATIONSHIP | MISSING_EVIDENCE | UNSUPPORTED_REPRESENTATION |
|---|---:|---:|---:|---:|---:|
| mozjpeg (tree − jchuff.c) | 118 | 28 | 1 | 88 | 1 |
| nss/lib/freebl (pilot) | 352 | 16 | 92 | 236 | 8 |

**Bucket definitions** (from the producers' own output, not a new scoring scheme):
- `DETERMINISTIC` — `disposition ∈ {deterministic_complete, proven_oversized}` (or the v1
  passthrough equivalent `analysis_status == deterministic_complete`): the write-length/
  count vs. destination-capacity relationship **is** established — safe or provably
  oversized, either way decided.
- `OPEN_RELATIONSHIP` — `relationship_unresolved` / `capacity_relation_not_established`
  (routes `range_arithmetic_review`, `semantic_relationship_review`): capacity is bound,
  but the length/count expression's relationship to it is not.
- `MISSING_EVIDENCE` — `additional_evidence_required` / `required_evidence_absent`:
  capacity itself (base array, allocation extent, or destination identity) is not bound.
- `UNSUPPORTED_REPRESENTATION` — the producer recognized a write-shaped call at all, but
  the specific representation defeats it structurally: `unknown_allocator_contract`
  (`sizeof`-driven heap size whose semantics aren't modeled) or cap3's
  `binding=mismatch/unavailable` (structural for-loop proof unavailable for that write).

By producer (candidate counts):

| Producer | mozjpeg | nss/freebl |
|---|---:|---:|
| base_v1v2 (frozen v1 + stack-capacity v2) | 19 | 287 |
| cap1 — `&(base[index])` | 0 | 12 |
| cap2 — transparent wrapper summaries | 31 | 27 |
| cap3 — advancing-pointer struct-member walks | 68 | 17 |
| cap4 — counted-loop writers | 0 | 9 |

## What the DETERMINISTIC findings actually are (sanity check, not promotion)

- **mozjpeg, all 28**: `GETENV_S` (a `strncpy`-based env-var read wrapper, resolved via
  cap2's interprocedural wrapper summary) into fixed 2- and 30-byte local buffers in
  `init_simd`/`main`/`jinit_memory_mgr` — length is a literal ≤ the destination capacity in
  every case. Correctly decided safe; not a candidate for anything.
- **nss/freebl, 16**: a mix of `s_mp_mul_comba_{4,8,16,32}` (bignum multiply into a
  fixed-size local limb array, count matches array size), several EC `sign_digest`/
  `verify_digest` functions writing a fixed-width digest/signature into a
  correctly-sized local buffer, and `eme_oaep_decode`/`camellia_setup192`/`fe_frombytes`
  — same shape. All read as genuinely safe on inspection; none flagged oversized in this
  pilot. (A `proven_oversized` finding would be the interesting case to hand-verify next;
  none occurred here.)

## OPEN_RELATIONSHIP — where a human/LLM review would actually add value

nss/freebl's 92 open-relationship candidates are dominated by `capacity_relation_not_established`
on real cryptographic buffer writes where the *destination* is bound (a local/stack array of
known size) but the *length expression* is symbolic — e.g. `AESKeyWrap_Winv` writing
`outLen` bytes into `output`, `AESKeyWrap_EncryptKWP` writing `inputLen` bytes into `newBuf`,
`blake2b_Compress` writing `BLAKE2B_BLOCK_LENGTH` bytes into a 16-`uint64_t` array (length
expression's relationship to the byte-vs-element unit isn't simplified). These are exactly
the class the producers are designed to flag and hand off (`llm_eligible: true` on all of
them) rather than resolve themselves — not evidence of a bug, evidence of "worth a closer
look," consistent with the frozen scanner's own posture everywhere else it's been run.

## MISSING_EVIDENCE / UNSUPPORTED_REPRESENTATION — coverage gaps, not findings

- `unknown_allocator_contract` (1 mozjpeg, 8 nss) — heap-context-resurrect functions
  (`BLAKE2B_Resurrect`, `MD2_Resurrect`, `MD5_Resurrect`, `SHA256_Resurrect`,
  `SHA512_Resurrect`, …) writing `sizeof(*ctx)`/`sizeof(ContextType)` bytes into a
  pointer whose allocation-site semantics the producers don't model. Same shape as the
  `unknown_allocator_contract` gap the definitive branch's own capability-plan docs
  already track (heap capacity from an allocator whose contract isn't in the frozen list).
  Nothing new; corroborates a documented gap on different real functions.
- cap3's 68 mozjpeg / 17 nss `MISSING_EVIDENCE` findings are dominated by
  `cursor_advance_ambiguous` / `cursor_advance_non_unit` / `destination_identity_ambiguous`
  / `cursor_trajectory_reset` — real advancing-pointer struct-member writes cap3
  recognized the *shape* of but where the structural for-loop proof (or the cursor's
  advance-by-exactly-one-element property) doesn't hold cleanly on the real code's control
  flow. Recorded as coverage data for cap3's own future tightening, not acted on here.

## Caveats on this report's own tooling (not the frozen scanner's)

- **`file` attribution is a best-effort name join**, not the frozen `physical_write_identity`
  (which resolves through the CPG's declaration-reference edges). A function name that
  collides across files in the same translation unit set (common for `static` helpers
  with generic names, or per-arch variants like `init_simd`) is reported as
  `AMBIGUOUS(name-collision:N files)` rather than guessed — this hit **7** mozjpeg findings
  and **~15%** of the nss set. `physical_write_identity_simplified` in each finding record
  is `file|function|line|dest_expr`, explicitly labeled non-authoritative in the driver's
  own docstring; cap2/cap4's own `underlying_write` field (present on their records) *is*
  the frozen WSD identity and should be preferred wherever it's populated.
- Full findings (all 470 candidates, every field) are in
  `raw_outputs/{mozjpeg,nss_freebl}.moz_scan_findings.json` (not duplicated in this report).

## Scoping the complete feasible source scope (decision needed before spending more compute)

- **mozjpeg**: this pilot **is** effectively the complete feasible scope for the current
  source tree (one file excluded and documented above; everything else parsed). No further
  mozjpeg scanning is planned unless `jchuff.c` gets a bespoke exclusion-narrowed pass
  (e.g. c2cpg `--exclude-regex` down to just `encode_one_block`, scanning the rest of that
  one file) — cheap, but low value: it's exactly the pointer-increment write shape already
  documented as out of scope for this producer set.
- **nss**: `lib/freebl/` (this pilot) is **one of 20 top-level `lib/` modules**. Two paths
  to widen it:
  1. **Header-only, include-auto-discovery** (what this pilot used) — cheap (~30s c2cpg,
     ~2min normalize per module at freebl's size) but only as reliable as each module's
     headers being locally resolvable; freebl worked because its dependencies (`util`,
     `mpi`, `ecl`) are sibling directories. `ssl`/`pk11wrap`/`softoken` pull NSPR types
     (`PRFileDesc`, `PRLock`, …) that aren't in the source tree at all — this path would
     need NSPR's public headers only (not a full NSPR build) added as an `--include`.
  2. **Full build via `build.sh`** (NSPR checkout + gyp/ninja) — this is what a prior
     session's `/tmp/nss-crypto-scan`/`/tmp/nss-ssl-scan` artifacts (dated Aug 26-27,
     found on disk, not reused here — this pilot re-clones and re-pins fresh per the
     "pin each repository commit" requirement) appear to have done, given a real
     77MB `cpp.json` with resolved facts across `src/` including `ssl`. Slower to set
     up, but the only reliable path to `ssl`/`softoken`/`pk11wrap`.
- **Recommendation**: path 1 (NSPR public headers via `--include`, no build) probably
  reaches most of the remaining `lib/` modules cheaply; `ssl` and `softoken` are the two
  most real-world-relevant modules not yet covered given NSS's known bug history
  (`pk11wrap`, `softoken` came up repeatedly in the old TChecker NSS corpus). Not started
  this round — flagging for the next one rather than silently expanding scope without
  reporting back first, per "run a bounded pilot first, then the complete feasible source
  scope" as two explicit, separately-reportable steps.
