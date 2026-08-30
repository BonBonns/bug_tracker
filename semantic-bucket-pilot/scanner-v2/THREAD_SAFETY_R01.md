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

## What's out of scope here

- **No detection capability.** `oob_runtime_capacity_verdict`-equivalent for lock-safety
  (recognize a missing-unlock-before-return pattern, etc.) is unbuilt. Building one and
  measuring it against `study/postcutoff_thread/FROZEN_heldout.json` is the natural next
  step, mirroring exactly how Capability 1 followed the write property's own corpus freeze.
- **LOCK/UNLOCK evidence beyond wolfSSL** — pthreads/Zephyr/kernel/NSPR/Win32 entries are
  standard-API assumptions, not verified against real headers one by one the way `wc_LockMutex`
  was. A pass reading Zephyr's actual mutex API naming against its real bug sites (mirroring
  how `XMEMCPY` was confirmed for wolfSSL) would likely recover more sites.
- **No re-audit of the write-property corpus for false negatives caused by lock-related CWE
  mislabeling** — the `case_644b3e3c`/`case_e062ef20` CWE-122 mislabeling found here is the
  same *direction* of noise (a real bug tagged with an unrelated CWE) as the write property's
  own multi-CWE false positives, just pointing the other way; not chased further this round.
- **SecVulEval pilot** — not attempted for this property at all.
