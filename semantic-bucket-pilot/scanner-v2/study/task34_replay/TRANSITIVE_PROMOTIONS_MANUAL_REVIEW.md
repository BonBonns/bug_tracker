# Manual review: the 5 real reportable=True findings (task #34's own first ever)

Per direct instruction ("the next highest-value review population is the five transitive
promotions... manually validate those five candidates first"), reviewed BEFORE any further
scanning, with the same rigor as `NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` -- real published
tarballs fetched and read directly, never assumed from the scanner's own output alone.

**Verdict: all 5 are FALSE POSITIVES.** Two distinct, real, structural root causes, neither
specific to the package it happened to surface on first.

## 1-2. `@abandonware/bluetooth-hci-socket@0.5.3-12` -- `bindRaw`, 2 OOB_WRITE candidates

`src/BluetoothHciSocket.cpp:279` (`memset(_address, 0, sizeof(_address))`) and `:284`
(`memcpy(_address, &di.bdaddr, sizeof(di.bdaddr))`). `_address` is declared
`uint8_t _address[6]` (`BluetoothHciSocket.h:111`) -- the scanner's own `dest_capacity_bytes: 6`
is correct. `di.bdaddr` is `bdaddr_t` (`struct hci_dev_info`, the real, standard Linux BlueZ
type) -- a Bluetooth device address, always exactly 6 bytes.

**Root cause: a real "wrong-looking sizeof" shape that is NOT actually wrong.** Line 279's
`sizeof(_address)` on an array correctly evaluates to 6 at compile time -- purely self-
referential, cannot overflow. Line 284's `sizeof(di.bdaddr)` names a DIFFERENT variable than the
destination (`_address`) -- syntactically the same shape `OOB_COMPARE`'s own real "wrong sizeof"
detector target looks for -- but `di.bdaddr`'s own real, fixed type size (6 bytes) happens to
exactly equal `_address`'s own real capacity (6 bytes). The write extent the scanner derived
does not syntactically match the destination's own name, so `CPP_FIXED_ARRAY_INDEX_UNBOUNDED`-
style extent derivation could not confirm it statically -- but the REAL numeric values, read
directly from both real type declarations, match exactly. Not a vulnerability: a real, disclosed
precision gap in cross-variable capacity matching, the same class of imprecision the OOB_INDEX_
WRITE stratified audit already flagged for its own detector.

## 3-5. `mtx_lock` / `rwlock_rdlock` (`@confluentinc/kafka-javascript@1.10.0`) and `lock`
(`@eliyya/sange@1.2.0`) -- 3 LOCK_BALANCE candidates

All 3 share the EXACT same real root cause, confirmed independently on two unrelated real
codebases:

- `mtx_lock` (`deps/librdkafka/src/tinycthread.c:110`): a real, well-known cross-platform
  threading-primitive WRAPPER. Its own body calls the underlying OS primitive
  (`EnterCriticalSection`/`pthread_mutex_lock`) and RETURNS -- it never calls `mtx_unlock`
  itself, by design; releasing is the CALLER's own responsibility, in a SEPARATE function
  (`mtx_unlock`, defined separately in the same file). `rd_refcnt_sub0` (`rd.h:353`), the real
  function the reachability path resolves through, correctly calls BOTH `mtx_lock(&R->lock)`
  AND `mtx_unlock(&R->lock)`, directly adjacent, on one straight-line path -- genuinely balanced,
  confirmed by direct inspection.
- `rwlock_rdlock` (`deps/librdkafka/src/tinycthread_extra.c`): the same real shape -- a
  primitive-acquiring wrapper, never expected to release within its own body.
- `lock` (`@eliyya/sange`'s own `Mutex::lock()`, `src/thread.h:11`): `int lock(){ return
  pthread_mutex_lock(&mutex); }` -- a real, one-line wrapper; `unlock()` is a separate sibling
  method three lines later (`src/thread.h:15`).

**Root cause: a real, structural LOCK_BALANCE scanner-design mismatch, not a missing-unlock
bug.** `lock_balance_verdict.py`'s own candidate generation scans every function in the corpus
for a call matching a lock-acquisition pattern, then asks "does THIS SAME enclosing function
also call the matching release?" -- correct and validated for an ORDINARY application function
that acquires and releases a lock across its own control flow (its own real positive control,
`Dtls13RtxAddAck`, is exactly this shape). It was never designed to be asked about the
lock-PRIMITIVE-DEFINING function itself (`mtx_lock`, `rwlock_rdlock`, `Mutex::lock`) -- a
function whose ENTIRE real contract is "acquire and return," with release delegated to a
separate function or the caller, by architecture, not by omission. `NO_RELEASE_ANYWHERE_IN_
FUNCTION` is a real, accurate description of these functions' own bodies -- it is simply the
wrong question to ask of them.

**Why the transitive-reachability tier surfaced this now, and not before:** these 3 candidates
have almost certainly existed as raw LOCK_BALANCE candidates in EVERY package that bundles
tinycthread.c/a similar wrapper (a real, corpus-wide pattern, not package-specific) since task
#36 first enabled LOCK_BALANCE -- but stayed `TIER_INTERNAL_UNREGISTERED` (correctly: `mtx_lock`/
`rwlock_rdlock`/`Mutex::lock` are never themselves registered N-API exports) until task #32's
reopened transitive-call tier made them, technically correctly, "reachable" -- reachability was
never the actual gap for these three; the gap is that the scanner's own candidate identity
(which FUNCTION is "the one under review") targets the primitive, not a real application-level
caller.

## Adjudication

All 5 recorded in `adjudication_registry.py` as `CONFIRMED_FALSE_POSITIVE`, citing this document,
exact-match only (same discipline as node-libcurl's own entry) -- never a blanket rule excluding
"any function named lock/mtx_lock/etc." by pattern, which would be exactly the kind of guessed
adjudication this pipeline's own discipline forbids.

## Recommendation (not built here, per direct instruction's own scope -- validation first)

The LOCK_BALANCE root cause is real and general, not incidental to these 3 sites: a future task
should teach `lock_balance_verdict.py` to recognize a "pure acquire" function shape (a lock-call
followed by nothing but a return, with no other control flow) and either exclude it from
candidate generation entirely or reclassify it as a distinct, disclosed abstention -- rather than
relying on this document's own per-site adjudications to keep re-catching the same real pattern
on every future package that bundles the same tinycthread-shaped wrapper. Not attempted in this
review; per direct instruction, this was validation, not a new capability build.

---
*Real tarballs fetched and read directly for all 3 packages
(`@abandonware/bluetooth-hci-socket@0.5.3-12`, `@confluentinc/kafka-javascript@1.10.0`,
`@eliyya/sange@1.2.0`) -- nothing in this review is inferred from the scanner's own output alone.*
