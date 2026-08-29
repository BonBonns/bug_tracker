/*
 * Dynamic reachability probe for the softoken "constant-time MAC" init
 * path (lib/softoken/sftkhmac.c: SetupMAC() -> sftk_HMACConstantTime_New()
 * / sftk_SSLv3MACConstantTime_New()), which is the only production caller
 * of lib/freebl/hmacct.c's static MAC() (via HMAC_ConstantTime() /
 * SSLv3_MAC_ConstantTime()).
 *
 * hmacct.c's MAC() copies the HMAC secret into a fixed-size local buffer:
 *     unsigned char hmacPad[HASH_BLOCK_LENGTH_MAX];   // 144 bytes
 *     PORT_Assert(macSecretLen <= sizeof(hmacPad));    // compiled out w/ NDEBUG
 *     memcpy(hmacPad, macSecret, macSecretLen);
 *
 * The question under test: can a caller reach that memcpy with
 * macSecretLen > sizeof(hmacPad) via the only production call path
 * (the PKCS#11 C_SignInit dispatch for CKM_NSS_HMAC_CONSTANT_TIME /
 * CKM_NSS_SSL3_MAC_CONSTANT_TIME), or does SetupMAC()'s own bound
 * (secretLength > sizeof(ctx->secret), i.e. > 64) reject it first?
 *
 * This program invokes ONLY the MAC init call (PK11_CreateContextBySymKey),
 * never Update/Digest, so it can't itself force the copy to happen -- it
 * measures whether NSS lets an oversized key get that far in the first
 * place. It uses a private, isolated on-disk NSS DB created fresh under a
 * temp directory (see run.sh), never touching any shared/system DB.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nss.h"
#include "pk11pub.h"
#include "prerror.h"
#include "secitem.h"
#include "pkcs11n.h" /* CKM_NSS_HMAC_CONSTANT_TIME, CK_NSS_MAC_CONSTANT_TIME_PARAMS */

/* sizeof(sftk_MACConstantTimeCtx.secret) from lib/softoken/pkcs11i.h */
#define SFTK_MAC_SECRET_BUF 64

/* Returns: 1 = init succeeded with keyLen > SFTK_MAC_SECRET_BUF (the actual
 *              question under test: an oversized key reached the MAC
 *              context); 0 = rejected, or accepted but within the safe
 *              bound (<=64 bytes, well under hmacct.c's 144-byte buffer). */
static int
try_one(const char *label, unsigned int keyLen, CK_MECHANISM_TYPE macType,
        CK_MECHANISM_TYPE macAlg)
{
    unsigned char *keyBuf = malloc(keyLen ? keyLen : 1);
    memset(keyBuf, 0x42, keyLen);

    SECItem keyItem;
    keyItem.type = siBuffer;
    keyItem.data = keyBuf;
    keyItem.len = keyLen;

    PK11SlotInfo *slot = PK11_GetInternalSlot();
    if (!slot) {
        fprintf(stderr, "[%s] PK11_GetInternalSlot failed\n", label);
        free(keyBuf);
        return 2;
    }

    /* Import an arbitrary-length raw secret as a generic PKCS#11 key
     * object -- this is the "oversized secret key" creation/import step.
     * Nothing here bounds keyLen; NSS creates the key object regardless. */
    PK11SymKey *symKey = PK11_ImportSymKey(slot, CKM_GENERIC_SECRET_KEY_GEN,
                                            PK11_OriginUnwrap, CKA_SIGN,
                                            &keyItem, NULL);
    PK11_FreeSlot(slot);
    if (!symKey) {
        printf("[%s] keyLen=%-4u  key IMPORT rejected: %s\n",
               label, keyLen, PR_ErrorToName(PR_GetError()));
        free(keyBuf);
        return 0; /* rejected before we even got to the MAC mechanism -- safe */
    }

    /* Build the CK_NSS_MAC_CONSTANT_TIME_PARAMS exactly as
     * ssl3_ComputeRecordMACConstantTime() does, with a realistic 13-byte
     * TLS record header (<= sizeof(ctx->header)==75, so that check never
     * confounds the result we're after). */
    unsigned char header[13];
    memset(header, 0, sizeof(header));

    CK_NSS_MAC_CONSTANT_TIME_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.macAlg = macAlg;
    params.ulBodyTotalLen = keyLen + sizeof(header) + 32;
    params.pHeader = header;
    params.ulHeaderLen = sizeof(header);

    SECItem param;
    param.type = siBuffer;
    param.data = (unsigned char *)&params;
    param.len = sizeof(params);

    /* *** THE MAC INITIALIZATION CALL UNDER TEST ***
     * This, and only this, is what dispatches into softoken's
     * NSC_SignInit() -> case CKM_NSS_HMAC_CONSTANT_TIME ->
     * sftk_HMACConstantTime_New() -> SetupMAC(). No Update/Digest/Finalize
     * is ever performed, so any crash or ASan report below can only come
     * from the init path itself. */
    PK11Context *ctx = PK11_CreateContextBySymKey(macType, CKA_SIGN, symKey, &param);

    if (!ctx) {
        printf("[%s] keyLen=%-4u  MAC-INIT REJECTED (validation held): %s\n",
               label, keyLen, PR_ErrorToName(PR_GetError()));
        PK11_FreeSymKey(symKey);
        free(keyBuf);
        return 0; /* rejected -- safe */
    }

    int oversized = keyLen > SFTK_MAC_SECRET_BUF;
    printf("[%s] keyLen=%-4u  MAC-INIT SUCCEEDED%s\n",
           label, keyLen,
           oversized ? "  *** OVERSIZED KEY ACCEPTED ***" : " (within safe bound)");
    PK11_DestroyContext(ctx, PR_TRUE);
    PK11_FreeSymKey(symKey);
    free(keyBuf);
    return oversized ? 1 : 0;
}

int
main(void)
{
    const char *dbdir = getenv("NSS_TEST_DB_DIR");
    if (!dbdir) {
        fprintf(stderr, "NSS_TEST_DB_DIR must point at an isolated temp NSS DB dir\n");
        return 2;
    }

    char configDir[1024];
    snprintf(configDir, sizeof(configDir), "sql:%s", dbdir);

    if (NSS_Initialize(configDir, "", "", "", NSS_INIT_READONLY | NSS_INIT_NOCERTDB |
                                                   NSS_INIT_NOMODDB) != SECSuccess) {
        fprintf(stderr, "NSS_Initialize failed: %s\n",
                PR_ErrorToName(PR_GetError()));
        return 2;
    }

    printf("== NSS initialized against isolated DB: %s ==\n", dbdir);
    printf("== HASH_BLOCK_LENGTH_MAX (hmacct.c hmacPad capacity) = %d\n", HASH_BLOCK_LENGTH_MAX);
    printf("== sftk_MACConstantTimeCtx.secret capacity           = %d\n\n", SFTK_MAC_SECRET_BUF);

    int anySucceeded = 0;
    unsigned int lens[] = { 16, 64, 65, 100, 144, 145, 200, 1000, 65536 };
    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        int rv = try_one("CKM_NSS_HMAC_CONSTANT_TIME", lens[i],
                          CKM_NSS_HMAC_CONSTANT_TIME, CKM_SHA256_HMAC);
        if (rv == 1)
            anySucceeded = 1;
    }
    printf("\n");
    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        int rv = try_one("CKM_NSS_SSL3_MAC_CONSTANT_TIME", lens[i],
                          CKM_NSS_SSL3_MAC_CONSTANT_TIME, CKM_SSL3_SHA1_MAC);
        if (rv == 1)
            anySucceeded = 1;
    }

    NSS_Shutdown();

    printf("\n== RESULT: %s ==\n",
           anySucceeded
               ? "at least one key >64 bytes REACHED the MAC context (needs Update() to confirm memcpy overflow)"
               : "every key >64 bytes (up to and beyond hmacct.c's 144-byte hmacPad) was rejected at MAC-init time; "
                 "hmacct.c's MAC() memcpy was never reached with an unvalidated length");
    return anySucceeded ? 10 : 0;
}
