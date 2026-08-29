# Manual audit — `lib/softoken/pkcs11c.c::sftk_doSSLMACInit()`

Hand-chased lead from `NSS_SCOPE_EXPANSION_softoken_ssl.md` ("a PKCS#11
attribute-length-driven key copy; worth a look given this session's own `hmacct.c`
audit already found a real gap in a related MAC-key-handling path"). Traced by hand
against the pinned `mozilla/nss@7b5f00b` tree — no CVE list consulted.

## The flagged write

```c
// lib/softoken/pkcs11i.h:440-450
struct SFTKSSLMACInfoStr {
    size_t size;               /* must be first */
    void *hashContext;
    SFTKBegin begin;
    SFTKHash update;
    SFTKEnd end;
    CK_ULONG macSize;
    int padSize;
    unsigned char key[MAX_KEY_LEN];   // MAX_KEY_LEN = 256 (pkcs11i.h:74)
    unsigned int keySize;
};

// lib/softoken/pkcs11c.c:2532-2549
keyval = sftk_FindAttribute(key, CKA_VALUE);
if (keyval == NULL)
    return CKR_KEY_SIZE_RANGE;
context->hashUpdate(context->hashInfo, keyval->attrib.pValue,
                    keyval->attrib.ulValueLen);
...
sslmacinfo = (SFTKSSLMACInfo *)PORT_Alloc(sizeof(SFTKSSLMACInfo));   // fixed-size heap chunk
...
PORT_Memcpy(sslmacinfo->key, keyval->attrib.pValue,
            keyval->attrib.ulValueLen);                              // THE WRITE
sslmacinfo->keySize = keyval->attrib.ulValueLen;
```

`keyval->attrib.ulValueLen` is the `CKA_VALUE` attribute length of a PKCS#11
`CKO_SECRET_KEY` object — i.e. it comes from whatever created that key object, not
from anything `sftk_doSSLMACInit` itself controls or clamps.

## Every check between "key object" and this write, traced

`sftk_InitGeneric` (`pkcs11c.c:549-617`, called by both `NSC_SignInit` and
`NSC_VerifyInit` before their mechanism `switch`) validates:
- the key's object class (`CKO_SECRET_KEY`),
- `CKA_SIGN`/`CKA_VERIFY` is true,
- the `CKA_KEY_TYPE` attribute's length equals `sizeof(CK_KEY_TYPE)`.

**It never reads or bounds `CKA_VALUE`'s length at all.** `sftk_doSSLMACInit` itself
checks only that `keyval != NULL` (`CKR_KEY_SIZE_RANGE` on a *missing* attribute, not a
*too-large* one). Grepped `MAX_KEY_LEN` across all of `lib/softoken`: exactly one
comparison against it anywhere in the tree (`pkcs11c.c:7946`, inside key-derivation
code, an unrelated function/call path). **No check anywhere on this call path enforces
`ulValueLen <= MAX_KEY_LEN` before the `PORT_Memcpy`.**

## The sibling implementation of the SAME mechanism does check this

The earlier `hmacct.c` audit already traced a *different* implementation of the
identical SSLv3-MAC PKCS#11 mechanisms: `sftk_SSLv3MACConstantTime_New` / `SetupMAC()`
in `lib/softoken/sftkhmac.c`, which holds the equivalent secret in a **64-byte**
`ctx->secret[64]` field and has a real, unconditional guard:

```c
// sftkhmac.c:69,86-88
unsigned char secret[sizeof(ctx->secret)];   // 64 bytes
...
if (secretLength > sizeof(secret)) {
    return NULL;
}
```

Two independent implementations of `CKM_SSL3_MD5_MAC`/`CKM_SSL3_SHA1_MAC` coexist in
this tree: the constant-time one (`sftkhmac.c`, reached only through NSS's own
internal, non-PKCS#11 fast path that `ssl3con.c` calls directly for record MACing —
already traced in `AUDIT_hmacct_MAC.md`) genuinely bounds its secret; the plain one
audited here (`pkcs11c.c`, reached through the **generic public PKCS#11 mechanism
dispatch**, `NSC_SignInit`/`NSC_VerifyInit`'s `switch (pMechanism->mechanism)`) does
not bound its secret at all. This isn't two attempts at the same check with one
buggy — it's one path that has the check and a completely separate path, for the same
named cryptographic operation, that never inherited it.

## Verdict: real, unconditional heap buffer overflow — reachable by any PKCS#11 API caller, not by ordinary TLS traffic

- **Not attacker-reachable through NSS's own TLS/SSL code.** `ssl3con.c` never calls
  `NSC_SignInit`/`NSC_VerifyInit` with these mechanisms for record MACing — it uses the
  constant-time internal path (`AUDIT_hmacct_MAC.md`'s own finding), which derives
  fixed 16/20-byte MAC secrets from the handshake, never an application-chosen length,
  and which DOES bound-check as shown above. Network-supplied TLS record data cannot
  reach this specific function through the normal Firefox/NSS TLS stack.
- **Reachable by any PKCS#11 API caller.** `softoken` (`softokn3`) is a general-purpose
  loadable PKCS#11 module; `CKM_SSL3_MD5_MAC`/`CKM_SSL3_SHA1_MAC` are ordinary entries
  in its public mechanism table, not gated to internal-only use. Any process that loads
  softoken as a PKCS#11 provider (any application linking NSS as a generic crypto
  library, a third-party PKCS#11 consumer, or NSS's own certutil/pk12util-style
  tooling if it ever exercises this mechanism) can: (1) create a `CKO_SECRET_KEY`
  object via `C_CreateObject`/key derivation with a `CKA_VALUE` longer than 256 bytes
  — nothing in the object-creation path this audit traced rejects an oversized
  symmetric-key value for generic secret-key objects — then (2) call
  `C_SignInit`/`C_VerifyInit` with mechanism `CKM_SSL3_MD5_MAC` or `CKM_SSL3_SHA1_MAC`
  on that key handle. Step 2 alone triggers the overflow: `PORT_Memcpy` writes
  `ulValueLen` bytes into the 256-byte `key` field of a `PORT_Alloc(sizeof(
  SFTKSSLMACInfo))` heap chunk, overrunning it by `ulValueLen - 256` bytes into
  adjacent heap memory, for any `ulValueLen > 256` (up to `CK_ULONG`'s range —
  no upper bound is enforced at all, not even a large sanity ceiling).
- **This audit did not verify** whether any other softoken caller (a token-policy
  layer, a FIPS-mode restriction, or an object-creation-time attribute template
  validator elsewhere in the tree outside `pkcs11c.c`/`pkcs11i.h`) independently
  rejects oversized `CKA_VALUE` for a generic `CKO_SECRET_KEY` object before it ever
  reaches this code — that would be the concrete next step were this to be escalated,
  same "not verified further" caveat the earlier audit gave its own PKCS#11-caller
  scope note.

## Bottom line

A genuine, unconditional heap buffer overflow in a legacy PKCS#11 mechanism
implementation, contrasted directly against a sibling implementation of the SAME
mechanism that DOES bound the same value. Not reachable via ordinary Firefox/NSS TLS
traffic (that path uses the other, bounded implementation) — reachable via the generic
PKCS#11 API by any caller able to create an oversized secret-key object and invoke
`C_SignInit`/`C_VerifyInit` with `CKM_SSL3_MD5_MAC`/`CKM_SSL3_SHA1_MAC`. Worth a real
hardening patch (`if (keyval->attrib.ulValueLen > sizeof(sslmacinfo->key)) { ...
CKR_KEY_SIZE_RANGE ...}` before the `PORT_Memcpy`, mirroring `SetupMAC()`'s own
existing check on the same value) — not an emergency network-facing escalation, since
the trust boundary is "PKCS#11 API caller," not "TLS peer."
