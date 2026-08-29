# Manual audit — `lib/freebl/hmacct.c::MAC()`, both flagged writes

Bounded manual audit, as requested, before spending time on NSS expansion. Traced every
caller within the pinned `mozilla/nss@7b5f00b` tree by hand (not by the scanner) — array
capacities, the two writes' length/offset derivation, every call path, and whether
`PORT_Assert` actually protects anything in a release build (checked against real NSPR
source, not assumed).

## The two flagged writes

```c
unsigned char hmacPad[HASH_BLOCK_LENGTH_MAX];      // line 132, capacity = 144 bytes
unsigned char firstBlock[HASH_BLOCK_LENGTH_MAX];   // line 133, capacity = 144 bytes
...
152  PORT_Assert(macSecretLen <= sizeof(hmacPad));
153  memcpy(hmacPad, macSecret, macSecretLen);                    // WRITE 1
...
182      const unsigned int overhang = headerLen - mdBlockSize;   // unsigned subtraction
183      hashObj->update(mdState, header, mdBlockSize);
184      memcpy(firstBlock, header + mdBlockSize, overhang);       // WRITE 2
```

`HASH_BLOCK_LENGTH_MAX` = `SHA3_224_BLOCK_LENGTH` = **144** bytes (`blapit.h:119,124`).

## Every caller, traced to the root

`grep` across the whole pinned tree: exactly **one** call site reaches `MAC()` at all —
`lib/softoken/sftkhmac.c` (`sftk_HMACConstantTime_Update` / `sftk_SSLv3MACConstantTime_Update`).
Everything else (`loader.c`, `ldvector.c`) is a function-pointer dispatch table to the same
implementation, not a distinct caller.

```
sftk_SSLv3MACConstantTime_New()          [lib/softoken/sftkhmac.c:134-166]
  -> SetupMAC()                          [line 63-98]
       secretLength = keyval->attrib.ulValueLen   (from a PKCS#11 CKA_VALUE key object)
       if (secretLength > sizeof(secret)) return NULL;   <- REAL check, sizeof(secret)=64
                                                              (struct field: unsigned char
                                                              secret[64], pkcs11i.h:662)
  -> ctx->headerLength = ctx->secretLength + padLength + params->ulHeaderLen;
       padLength = 40 (SHA1) or 48 (MD5)     <- only these two algs permitted for SSLv3
  -> if (ctx->headerLength > sizeof(ctx->header)) goto loser;  <- REAL check, header[75]
       (NO LOWER-BOUND CHECK on ctx->headerLength anywhere)
```

`params->ulHeaderLen` (the one free variable) is set at exactly one place in the whole
tree: `lib/ssl/ssl3con.c:2243`, from `SSL_BUFFER_LEN(&header)` where `header` is built by
`ssl3_BuildRecordPseudoHeader()` — sequence number (8B) + content type (1B) + [version
(2B), only for TLS/included variants] + length (2B). For SSLv3 (`includesVersion` false):
**8+1+2 = 11 bytes, always**, a protocol-format constant, never derived from received
data length.

## Write 1 (`hmacPad`, line 153) — verdict: **not exploitable via the only known caller; the compiled-out assert is real but redundant**

`macSecretLen` reaching `MAC()` is `ctx->secretLength`, which `SetupMAC()` genuinely
bounds to `<= 64` with a real `if`/`return NULL` — **not** an assert, unconditional in
release builds. `hmacPad`'s capacity is 144. **64 <= 144 always holds** through this path.

Verified independently (not assumed) that `PORT_Assert` → NSPR's `PR_ASSERT` really does
compile to `((void)0)` outside `DEBUG`/`FORCE_PR_ASSERT`
(`nspr/pr/include/prlog.h:210-224`, cloned fresh and read directly). So the assert at
line 152 provides **zero** protection in a release build — but it's redundant, not load-
bearing: the real bound is `SetupMAC()`'s own unconditional check, one call frame up.
This confirms (with the exact bound values) what an earlier, separate scan of this same
function already flagged qualitatively ("MAC() itself has zero local enforcement beyond a
`PORT_Assert`") — worth fixing as defense-in-depth (the bound `MAC()` actually needs is
"macSecretLen <= 144", not "<= 64"; if any future caller ever supplies a secret between
65 and 144 bytes, `SetupMAC`'s check would reject it even though `MAC()` itself could
safely take it — a usability/whack-a-mole risk more than a safety one), **but not
currently reachable as an overflow** through the one call path this tree contains.

## Write 2 (`firstBlock`, line 184, SSLv3 branch) — verdict: **safe via the one real caller's invariant, but the invariant is not locally enforced — a genuine latent gap**

For the real (only) caller path: `headerLen = secretLength + padLength + 11`.
`secretLength` for an actual SSLv3/TLS MAC key is always the negotiated MAC key size
(16 bytes for MD5, 20 for SHA1 — fixed by the cipher suite, never attacker-shrinkable
through the SSL/TLS handshake code). So in practice `headerLen = 16+48+11 = 75` (MD5) or
`20+40+11 = 71` (SHA1) — **exactly** matching the function's own doc comment ("7 bytes
(SHA1) or 11 bytes (MD5)" of overhang) and an earlier scan's independently-cited "71/75
bytes." `mdBlockSize` is 64 for both MD5 and SHA1 (the only two algorithms
`sftk_SSLv3MACConstantTime_New` permits). `overhang = headerLen - 64` = 7 or 11, safely
inside `firstBlock`'s 144-byte capacity.

**But nothing in the traced code enforces `headerLength >= mdBlockSize` as an invariant.**
`SetupMAC()` only upper-bounds `secretLength` (`<= 64`); `sftk_SSLv3MACConstantTime_New`
only upper-bounds the assembled `headerLength` (`<= 75`). There is no check anywhere that
`secretLength + padLength + 11 >= 64`. If `secretLength` were ever small enough — e.g. a
PKCS#11 key object with `CKA_VALUE` length 0-12 used with mechanism
`CKM_SSL3_MD5_MAC`/`CKM_SSL3_SHA1_MAC` — `headerLength` would land below 64,
`overhang = headerLen - mdBlockSize` would **underflow as an `unsigned int`** to a value
near `UINT_MAX`, and `memcpy(firstBlock, header + 64, overhang)` would be a
several-gigabyte out-of-bounds read (from a 75-byte `ctx->header`) **and** write (into a
144-byte `firstBlock`) — a real heap/stack corruption, not a benign miscompare.

**Scope of what this rules in vs. rules out, precisely:**
- The only caller *found in this tree* (`ssl3con.c`'s internal SSL/TLS record-MAC code)
  cannot trigger this: it only ever supplies the fixed 16/20-byte negotiated MAC key
  length, never an application-chosen one.
- `softoken` is a general-purpose loadable PKCS-11 module, though — any application that
  loads it directly (not through NSS's own `libssl`) and calls `C_SignInit`/`C_VerifyInit`
  with mechanism `CKM_SSL3_MD5_MAC` or `CKM_SSL3_SHA1_MAC` on a short/empty key object
  would reach `SetupMAC()` with attacker/application-chosen `secretLength`, and this path
  has no other guard. **I have not searched beyond this one repository for such a
  caller** (Firefox's own PKCS#11 usage, other NSS embedders, or direct third-party
  PKCS#11 API consumers) — that would be the next concrete step, not something this
  bounded audit covers.
- The write only executes when `k > 0`, i.e. when there's enough total record data to
  need more than `varianceBlocks(2)+1` hash blocks — real, but unremarkable network-
  supplied record-length territory in the SSLv3-CBC-MAC-verification context this
  function exists for in the first place; not an extra obstacle worth much weight.

## Bottom line

- **Write 1**: false positive for exploitability, confirmed by tracing the real
  (non-assert) bound one frame up — not "the scanner was wrong to flag it" (the frozen
  scanner never claims unsafe, only "relationship not established" — correct, since
  `MAC()` itself indeed establishes nothing locally), but a settled, closed case: not
  independently reachable as an overflow via any caller this tree contains.
- **Write 2**: a genuine caller-contract gap. Not demonstrated exploitable through any
  caller in this repository (the one real path is safe by construction), but **the
  safety is borrowed entirely from that one caller's invariant, never checked locally**
  — exactly the shape of bug a defense-in-depth / hardening patch exists to close
  (`ctx->headerLength >= mdBlockSize`, or equivalently reject `secretLength` too small
  for the chosen algorithm's block size, in `SetupMAC`/`sftk_SSLv3MACConstantTime_New`).
  Worth a real patch proposal; not worth an emergency escalation absent a demonstrated
  external caller that can supply the small key.

No CVE list was consulted for this audit; the two candidate writes and their identity
came entirely from this session's frozen-scanner pilot run, and every claim above was
verified by reading the pinned source and, for the `PORT_Assert` semantics claim, a
freshly cloned copy of NSPR — not asserted from prior knowledge.
