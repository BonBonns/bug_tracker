# Dynamic reachability check: oversized HMAC secret vs. hmacct.c's `MAC()`

Follow-up to the flagged-but-unfiled item in `moz-scan-paired-cve-validation-round1.md`:

> Ran against already-generated real fact files and found + manually verified 4 live
> candidates (2 in `nss/lib/freebl/hmacct.c`'s Lucky13 `MAC()`, 2 in
> `nss/lib/ssl/sslsock.c`'s `ssl_WriteV`). All are safe, but the `hmacct.c` one only
> because a **separate module three directories away**
> (`lib/softoken/sftkhmac.c`'s PKCS#11 key-attribute handling) enforces a real runtime
> bound before ever calling in — `MAC()` itself has zero local enforcement beyond a
> `PORT_Assert` that compiles out in release.

That earlier verdict was reached by static reading. This round reproduces it dynamically:
build NSS with ASan, drive an oversized secret key through the *actual* production
call path, and record whether validation rejects it or ASan reaches the copy.

**Verdict: validation held. Reachability was NOT reproduced. No vulnerability is
claimed.**

## The code in question

`lib/freebl/hmacct.c`, static `MAC()` (pinned commit below):

```c
unsigned char hmacPad[HASH_BLOCK_LENGTH_MAX]; /* == SHA3_224_BLOCK_LENGTH == 144 bytes */
...
memset(hmacPad, 0, mdBlockSize);
PORT_Assert(macSecretLen <= sizeof(hmacPad)); /* PR_ASSERT: no-op unless DEBUG is defined */
memcpy(hmacPad, macSecret, macSecretLen);
```

`MAC()` has exactly one production caller path: `HMAC_ConstantTime()` /
`SSLv3_MAC_ConstantTime()`, invoked from `lib/softoken/sftkhmac.c`'s
`sftk_HMACConstantTime_Update()` / `sftk_SSLv3MACConstantTime_Update()`. Those in turn
only run on a context built by `sftk_HMACConstantTime_New()` /
`sftk_SSLv3MACConstantTime_New()`, both of which call a shared `SetupMAC()`:

```c
unsigned char secret[sizeof(ctx->secret)]; /* ctx->secret is unsigned char[64] */
...
secretLength = keyval->attrib.ulValueLen;
if (secretLength > sizeof(secret)) {   /* i.e. > 64 */
    sftk_FreeAttribute(keyval);
    return NULL;
}
memcpy(secret, keyval->attrib.pValue, secretLength);
```

`ctx->secret` is a fixed 64-byte field — well under `hmacPad`'s 144-byte capacity — so
if this check holds, `macSecretLen` can never reach `MAC()` above the value that
`hmacPad` was sized for. Both `*_New()` functions are dispatched from PKCS#11
`C_SignInit`/`C_VerifyInit` (`lib/softoken/pkcs11c.c`, `case
CKM_NSS_HMAC_CONSTANT_TIME` / `case CKM_NSS_SSL3_MAC_CONSTANT_TIME`) — this is the
"MAC initialization path" the probe below invokes, and nothing else.

## Method

- NSS + NSPR built from source with `./build.sh --asan --disable-tests`, i.e. a real
  ASan instrumented build of `libsoftokn3`/`libnss3`/`libfreebl3`, gcc, DEBUG defined
  (so `PORT_Assert` is live as a backstop, not compiled out).
  - `nss` pinned at `7b5f00bfd3835fee76be428c55e60cdb3366182c`
  - `nspr` pinned at `35205360bebf33f277b1ccc898cd965633494a87`
- A throwaway NSS DB created fresh with `certutil -N -d sql:<mktemp -d> --empty-password`
  for this run only, deleted afterward. No shared/system NSS DB was touched.
- `mac_init_test.c` (this directory):
  1. Imports a raw secret of a chosen length as a PKCS#11 generic-secret key object via
     `PK11_ImportSymKey` — the "oversized secret key creation/import" step. Nothing
     bounds the length at import time.
  2. Calls **only** `PK11_CreateContextBySymKey(CKM_NSS_HMAC_CONSTANT_TIME /
     CKM_NSS_SSL3_MAC_CONSTANT_TIME, CKA_SIGN, key, params)` — the exact call NSS's own
     TLS code (`ssl3_ComputeRecordMACConstantTime` in `lib/ssl/ssl3con.c`) makes to set
     up a record MAC. This dispatches straight into `NSC_SignInit` →
     `sftk_{HMAC,SSLv3MAC}ConstantTime_New` → `SetupMAC`, and nothing past init: no
     `Update`/`Sign`/`Digest` is ever called, so any crash can only originate in the
     init path itself.
  3. Records success/failure and repeats for key lengths 16, 64, 65, 100, 144, 145,
     200, 1000, 65536 bytes, against both mechanisms.
- Run under `ASAN_OPTIONS=halt_on_error=0` so one detected overflow wouldn't hide
  later cases, though none occurred.

Reproduce with `./run.sh` in this directory (clones and builds NSS+NSPR at the pinned
commits into a temp dir, or reuses `NSS_SRC_ROOT` if already built there).

## Observed result

Full output in `observed_output.log`. Summary:

| keyLen (bytes) | CKM_NSS_HMAC_CONSTANT_TIME | CKM_NSS_SSL3_MAC_CONSTANT_TIME |
|---:|---|---|
| 16  | accepted (within safe bound) | accepted (within safe bound) |
| 64  | accepted (within safe bound) | **rejected** (SEC_ERROR_INVALID_ARGS) |
| 65  | rejected (SEC_ERROR_INVALID_ARGS) | rejected |
| 100 | rejected | rejected |
| 144 | rejected | rejected |
| 145 | rejected | rejected |
| 200 | rejected | rejected |
| 1000 | rejected | rejected |
| 65536 | rejected | rejected |

- Every key length above 64 bytes — including values at, just past, and far past
  `hmacPad`'s 144-byte capacity — was rejected at MAC-init time by `SetupMAC`'s
  `secretLength > sizeof(secret)` check, before any `Update`/memcpy could run.
  (The SSLv3 mechanism additionally rejects the legitimate 64-byte case too, because
  its own header-capacity check — `secretLength + padLength + headerLen <=
  sizeof(ctx->header)` i.e. 75 bytes — is stricter for that mechanism; that is a
  separate, independently-enforced bound, not the one under test.)
- No ASan report of any kind (no heap/stack-buffer-overflow, no other sanitizer
  finding) at any tested length, on either mechanism.
- No crash, no `PORT_Assert` abort.
- Process exit status 0 (all lengths classified safe).

## Conclusion

The static read holds up dynamically: `SetupMAC()` in `sftkhmac.c` is a real,
unconditional runtime gate (not compiled out, unlike the `PORT_Assert` inside
`MAC()` itself) that sits in front of every production caller of `hmacct.c`'s `MAC()`,
and it rejects any secret longer than 64 bytes — well below the 144-byte buffer `MAC()`
copies into — before the MAC context is even constructed. Across every length tested,
from 1 byte over the software bound up to 65536 bytes, no oversized key reached the
memcpy, and ASan reported nothing.

**This is not a vulnerability.** The `PORT_Assert` in `hmacct.c`'s `MAC()` is
dead-code protection today, contingent entirely on `SetupMAC()` continuing to enforce
its bound — worth hardening defensively (e.g. a real bounds check or `PORT_Assert`
that doesn't compile out) so a future change to either call site can't silently
reintroduce the overflow, but there is no reachable overflow as the code stands at the
pinned commit.
