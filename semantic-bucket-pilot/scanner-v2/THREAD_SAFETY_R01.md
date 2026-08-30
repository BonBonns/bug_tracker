# THREAD-R01: a new held-out corpus track for missing/incorrect lock-unlock pairing

A new property, parallel to the destination-capacity-write track this project has been
building (`POSTCUTOFF_WRITE_MAPPING_AUDIT.md`, `secvuleval_freeze.py`), for **thread-safety**
bugs: missing or incorrectly-placed lock/unlock calls. Corpus construction only, same
discipline as the write property's own freeze scripts — pre-register CWE scope (or, here,
the reason it was abandoned) and the two deterministic rules **before** inspecting any yield,
freeze, report counts. **No detection capability is built here** — that is a separate, later
undertaking, exactly as the write property's Capability 1 took its own dedicated round after
its corpus already existed.

## Motivation

Found while auditing the write-property corpus. Two wolfSSL sites (`case_644b3e3c`,
`case_e062ef20` — `dtls13.c`, missing `wc_LockMutex`/`wc_UnLockMutex` around a list
traversal and before early returns) were correctly excluded there as **not** destination-
capacity write bugs — but they are real, CVE-confirmed thread-safety bugs, verified against
the real diffs at the real pinned commits in that audit. That is the evidence seed for this
track's `LOCK`/`UNLOCK` regex (`wc_LockMutex`/`wc_UnLockMutex` are real wolfSSL wrappers, not
guessed).

## RULE 1: lock-SITE mapping — object identity, not function-name identity

A pre-freeze sanity test against the two real motivating sites, run **before** touching the
real dataset (same "test the tool against ground truth before freezing" discipline as the
recall-sensitivity checks elsewhere in this project), caught a real design bug: porting
`postcutoff_freeze.py`'s write-mapping rule directly — dedupe by unique `(kind, dest)` —
scored `case_644b3e3c` as `ambiguous`. It has **3 lock/unlock calls** (1 acquire + 2 releases,
one per exit path) on the **same mutex object**, which is the normal, coherent shape of a
single lock fix, not competing candidates.

**Fixed design:** RULE 1 dedupes by the lock **object expression** (e.g.
`&ssl->dtls13Rtx.mutex`) across the whole hunk, regardless of how many acquire/release calls
reference it. Multiple *different* objects in one hunk still can't be disambiguated and stay
`ambiguous` — mapped / ambiguous / no_lock_op_found, same three-way outcome shape as the write
property.

## RULE 2: family assignment — from diff structure only

`family_id = hash(primitive_family | op_shape)`, where `op_shape` is the frozen-sorted set of
`(change_kind, lock_kind)` pairs seen on the mapped object — `change_kind` ∈
`{ADDED, REMOVED, CONTEXT}` (which side of the diff the op is on; requires a NEW line-
extraction helper, `diff_hunk_lines_marked()`, that — unlike `postcutoff_freeze.py`'s
`diff_hunk_lines()` — keeps the leading `+`/`-`/` ` marker, since it's the primary signal
for lock-bug shape: missing-lock ADDED vs missing-unlock ADDED vs over-locking REMOVED).
This correctly separates, e.g., a from-scratch missing-lock fix
(`{(ADDED,lock_acquire),(ADDED,lock_release)}`) from a missing-unlock-on-one-path fix
(`{(ADDED,lock_release)}` alone) even when both are on the same object/family.

## A second real finding: CWE tags don't work as an inclusion filter for this property

Tried CWE-based inclusion first, mirroring the write property (`THREAD_CWE = {362, 366, 413,
414, 667, 820, 821}` — race condition, improper/missing/incorrect locking). Result: **zero**
sites matched at all, out of 38 CWE-filtered candidates. Checked why against the two real
motivating sites: **both are labeled `CWE-122` (heap overflow) only** in this dataset — no
concurrency CWE at all. A CWE-based filter here would have silently excluded the exact
evidence that motivated this track.

**Fix:** dropped CWE gating entirely for this property. `cwe_ids` is still recorded per
mapped site (informational), but inclusion is `binary_label==vulnerability_fix` + C/C++ diff
+ not-Magma-overlap, with **RULE 1's lock-object detection as the sole inclusion mechanism**
— a site either has a lock-op-shaped diff or it doesn't, the same way `no_write_found`
already gates the write property regardless of what CWE narrowing that pool.

## Result (same byte-identical PostCutoff-CVE snapshot as the write-property track)

```
sites after filters: 571  (from 706 vulnerability_fix records: -282 not-vuln-fix pre-filter
                           doesn't apply here / -96 not C/C++ / -39 Magma-overlap)
mapping: no_lock_op_found=564, mapped=5, ambiguous=2
MAPPED sites: 5   FAMILIES: 3   (12-gate: BELOW)
by repo: wolfssl/wolfssl: 5
by primitive family: wolfssl_wc_mutex: 5
```

| benchmark_id | CVE | op_shape | family |
|---|---|---|---|
| `case_644b3e3c` | CVE-2026-5264 | ADDED:lock_acquire, ADDED:lock_release | `famT_5ee9e12c` |
| `case_e062ef20` | CVE-2026-5264 | ADDED:lock_release | `famT_713794fa` |
| `case_267d5a93` | CVE-2026-5295 | ADDED:lock_release | `famT_713794fa` |
| `case_a6eb1f6d` | (none recorded) | ADDED:lock_release | `famT_713794fa` |
| `case_f21da596` | (none recorded) | ADDED:lock_acquire, ADDED:lock_release, CONTEXT:lock_release | `famT_a0687093` |

**All 5 manually verified against the real diffs at the real pinned commits** (same standard
as the write-property audits) — 100% precision on this pass, not a sample:
- `case_644b3e3c`/`case_e062ef20` — the original motivating `dtls13.c` sites.
- `case_267d5a93` — another `dtls13.c` missing `wc_UnLockMutex` before an early return (a
  DTLS 1.3 ACK-list-full guard), same object, different exit path.
- `case_a6eb1f6d` — `wolfSSL_RAND_bytes`, missing `wc_UnLockMutex(&globalRNGMutex)` before an
  early return after a reseed-check failure.
- `case_f21da596` — `wolfSSL_RAND_poll`, adds `wc_LockMutex`/`wc_UnLockMutex` around a DRBG
  reseed call and reclaims the lock after a call-out — the 3-op shape.

All 5 sites are wolfSSL, all on `globalRNGMutex` or `dtls13Rtx.mutex` — not surprising given
`LOCK`/`UNLOCK` currently only has confirmed real evidence for wolfSSL's `wc_LockMutex`/
`wc_UnLockMutex`; the other listed primitives (pthreads, Zephyr `k_mutex`, kernel spinlocks,
NSPR, Win32 critical sections) are standard-API assumptions, not individually re-verified
against a real header the way `wc_LockMutex` was — flagged here rather than presented as
equally evidenced. Zephyr in particular is a plausible source of more real sites this pass
missed if its actual concurrency-primitive naming differs from the assumed `k_mutex_lock`/
`k_mutex_unlock`.

## Honest conclusion

**5 mapped, 3 families — far below the 12-family gate.** This is Round 1 of a brand-new
property with a corpus of exactly one repo's one wrapper API so far: an honest, small,
verified yield, not an inflated one — same posture this project has taken with every other
corpus (SecVulEval's "insufficient", Juliet's "pipeline study, not a powered experiment").
No detection capability exists for this property yet; this file freezes the confirmatory
target a future capability would be measured against, nothing more.

## Capability 1: missing-unlock-before-return (`lock_balance_verdict.py`)

Built on the **real, Joern-derived raw facts** (`cfg_edges.tsv`, `calls.tsv`,
`arguments.tsv`, `returns.tsv` — the same exporter output the destination-capacity-write
capabilities consume), not a diff-text heuristic. For each registered lock-acquire call,
walks the real CFG forward, treating a matching unlock call **on the same object** (text-
identity match on the call's first argument, conservative/abstain-first, same posture as
the write property's capabilities) as a barrier; any `return` reachable without first
crossing that barrier is a `LOCK_LEAK_CANDIDATE` — open finding, never a certainty. `LOCK_
FUNCS`/`UNLOCK_FUNCS` reuse `thread_freeze.py`'s exact evidence-based registered-function
list.

**Two real design bugs found and fixed via fixture testing before any real-code
validation** (all 6 controls in `lockcap_probe.c`, run through real Joern):

1. **Lock-call success/failure branch confusion.** The naive version treated the lock
   call's own `if (LOCK(...) != 0) return err;` failure-return as if it were a leak — the
   object was never acquired on that path, so a return there is correct, not a bug.
   `cfg_edges.tsv` carries no true/false branch label, so this can't be read off raw CFG
   topology directly. Added `guard_success_start()`: locates the comparison call
   immediately downstream of the lock call (skipping Joern's intermediate non-Call CFG
   nodes) whose code contains the lock call's own code, then of its two successors,
   identifies the one that is **the** genuine failure branch by object identity — every
   forward path from it reaches a `return` before touching the SAME lock object via any
   LOCK/UNLOCK call — and starts the leak-search from the *other* successor instead. Two
   iterations were needed to get the "which branch is which" criterion right: an early
   version wrongly flagged `<operator>.minus` (just computing the literal `-1` for the
   return value) as "real work," and a later version wrongly flagged a failure branch that
   unlocks a **different, unrelated** object as non-trivial — both caught by the
   `negTwoObjectsBalanced`/`vulnMissingUnlock` fixture controls before any real code was
   touched.
2. **Off-by-one in the guard-search helper.** `next_call_nodes()` initially included its
   own start node as a "found" call (since the lock call itself is, trivially, a call),
   short-circuiting before ever walking to its successors. Caught by the same fixture
   suite returning identical (wrong) output across two supposedly-different fix attempts.

**Validated (`check_lock_balance.py`, 11/11):**
- All 6 synthetic controls (`lockcap_probe.c`): the missing-unlock bug flagged with
  *exactly* the real bug's return, not the guard's; the fixed version, the fully-balanced
  negative control, and the two-different-locks ambiguity control all correctly produce
  zero findings; the unregistered-lock-name negative control proves the registration table
  is load-bearing (same pattern as `PORT_Memcpy`'s own negative control on the write side).
- **Development-site recovery**: `Dtls13RtxAddAck` copied **verbatim** from the real
  vulnerable wolfSSL commit (`7efc962d`, the site `case_e062ef20`/CVE-2026-5264 was mapped
  from) — the capability flags **exactly** the two returns the real fix (`3034dd9e`) adds
  an unlock to (the duplicate-record path and the allocation-failure path), no more, no
  less, with the lock object correctly identified as `&ssl->dtls13Rtx.mutex`.
- **No false positive on the real fix**: the same function with the real fix applied
  produces zero findings.

**Limitation as originally reported (round 1), now resolved (round 2, below).**
`case_644b3e3c` (`Dtls13RtxRemoveCurAck`, the OTHER original motivating site) was **not**
recoverable by Capability 1: at its vulnerable revision the function has **no lock call at
all** — the bug is a totally absent critical section, not an existing lock with an
incomplete release. Capability 1's shape (missing-unlock-given-an-existing-lock) simply
doesn't apply there. Recognizing "a critical section that should exist but doesn't" needs a
DIFFERENT signal than "is there a call to a registered lock function" — see Capability 2.

## Capability 2: cross-function protected-field inference (`protected_field_verdict.py`)

Investigated the round-1 limitation directly rather than leaving it closed. The needed
signal turns out to already be present in the SAME raw facts Capability 1 uses: Joern
represents a field access (`ssl->dtls13Rtx.seenRecords`) as a `<operator>.fieldAccess`/
`<operator>.indirectFieldAccess` call whose `code` carries the full textual chain — no
exporter change needed.

**Method** (still single-translation-unit scope, not whole-program): for every function
holding a registered lock, compute the CFG node-set genuinely inside its critical section
(reusing Capability 1's exact guard-aware barrier-BFS unchanged). For every field-access
call, normalize away the base identifier (`ssl->dtls13Rtx.seenRecords` ->
`.dtls13Rtx.seenRecords`) and record whether it falls inside a critical section, and for
which lock-object signature. **Inference rule**: a field-path is "protected by lock L" only
if EVERY protected occurrence of it anywhere in the corpus agrees on the same L (conflicting
evidence -> abstain on that field entirely, never guess which lock is real). Given such an
L, any access to that field-path OUTSIDE any L-critical-section — including in a function
with no lock at all — is a `MISSING_LOCK_CANDIDATE`. A field-path with no protected
occurrence anywhere establishes no pattern and is never flagged.

**Two real false-positive classes found and fixed via a pre-freeze sanity check against the
real `xfn_probe.c` fixture (both real functions, same file, same vulnerable commit),
before any synthetic controls were even written:**

1. **Generic single-segment field names.** The first version flagged `.next`, `.heap`,
   `.epoch`, `.seq` in `Dtls13RtxRemoveCurAck` alongside the real `.dtls13Rtx.seenRecords`
   finding — all because `Dtls13RtxAddAck` happens to touch `cur->next`/`ssl->heap` etc.
   *incidentally* while holding its lock, which doesn't mean those specific fields need
   it (correlation, not causation). Every false positive found was a 1-segment path; the
   real bug and the lock object itself were both 2-segment. Fixed by requiring >=2 path
   segments as a precondition for the inference to even consider a field — a common short
   field name is far more likely to collide across unrelated struct types than a specific
   nested path.
2. **The lock object flagged as needing its own protection.** `ssl->dtls13Rtx.mutex`
   itself came back as a `MISSING_LOCK_CANDIDATE` "protected by" itself — its own
   acquire call's argument is evaluated before the lock is held (outside the region), its
   release calls' argument accesses are inside, so the mutex's own field-path picked up
   conflicting-looking evidence. Fixed by excluding any field-path that is ITSELF ever
   passed as a lock/unlock call's object argument anywhere in the corpus from ever being
   treated as protectable data.

**Validated (`check_protected_field.py`, 11/11):**
- **Development-site recovery**: the real `xfn_probe.c` fixture (both functions verbatim
  from commit `3034dd9e`) now produces **exactly 2 findings**, both
  `.dtls13Rtx.seenRecords` in `Dtls13RtxRemoveCurAck`, inferred protector correctly
  `.dtls13Rtx.mutex` — precisely the `case_644b3e3c` bug this capability was built to
  recover, with zero of the noise fields and zero self-referential lock-object finding.
- 3 synthetic controls: a consistently-protected field (no finding), a field never
  touched under any lock anywhere (no evidence, no finding), and a field protected by
  two DIFFERENT locks in different functions (ambiguous — abstains on both accesses,
  classified `AMBIGUOUS_MULTIPLE_PROTECTORS`, not silently dropped).
- Runs alongside Capability 1's own 11/11 suite with no interference (fully standalone
  script, shares only the LOCK_FUNCS/UNLOCK_FUNCS vocabulary and the barrier-BFS logic,
  duplicated rather than imported per this project's standalone-gate-script convention).

**Both original motivating sites are now covered, by two different capabilities matched
to their two different shapes**: `case_e062ef20` by Capability 1 (existing lock,
incomplete release), `case_644b3e3c` by Capability 2 (no lock at all, inferred from a
sibling function's correct usage of the same field).

**What Capability 2 does NOT claim.** This is correlation-based, single-TU evidence, not a
soundness proof: a flagged field-path might legitimately be accessed unprotected in code
that provably never runs concurrently (single-threaded init, a documented external
invariant), which this design has no way to know. Every finding is `MISSING_LOCK_CANDIDATE`
— open, never a certainty — same posture as Capability 1's `LOCK_LEAK_CANDIDATE`.

## What's out of scope here

- **Whole-program / cross-file protected-field inference.** Capability 2 only sees
  evidence within a single c2cpg export (effectively one file); a lock and the function
  missing it living in different translation units of a real multi-file build is invisible
  to it as implemented.
- **LOCK/UNLOCK evidence beyond wolfSSL** — pthreads/Zephyr/kernel/NSPR/Win32 entries are
  standard-API assumptions, not verified against real headers one by one the way `wc_LockMutex`
  was. A pass reading Zephyr's actual mutex API naming against its real bug sites (mirroring
  how `XMEMCPY` was confirmed for wolfSSL) would likely recover more sites.
- **Measurement against the remaining 3 corpus sites** (`case_267d5a93`, `case_a6eb1f6d`,
  `case_f21da596`) — `case_644b3e3c` (Capability 2) and `case_e062ef20` (Capability 1) are
  now both used for development-site recovery; the other 3 were not re-examined against
  either capability this round. `case_267d5a93` in particular, on closer reading of its real
  vulnerable revision, looks like it may be a capacity/overflow bug (unbounded ACK-list
  growth) whose fix incidentally touches lock/unlock code, not a genuine lock-balance bug in
  its own right — flagged here, not resolved.
- **No re-audit of the write-property corpus for false negatives caused by lock-related CWE
  mislabeling** — the `case_644b3e3c`/`case_e062ef20` CWE-122 mislabeling found here is the
  same *direction* of noise (a real bug tagged with an unrelated CWE) as the write property's
  own multi-CWE false positives, just pointing the other way; not chased further this round.
- **SecVulEval pilot** — not attempted for this property at all.
