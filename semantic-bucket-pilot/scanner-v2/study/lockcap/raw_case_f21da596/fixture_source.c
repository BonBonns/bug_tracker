// LOCK-SAFE corpus measurement: case_f21da596 (CVE bundle, wolfSSL global RNG).
// wolfSSL_RAND_bytes (locks globalRNGMutex around globalRNG use) and wolfSSL_RAND_poll
// (reseeds globalRNG via wc_RNG_DRBG_Reseed with NO lock at all) copied close to verbatim
// from the real vulnerable commit 31490ab8, simplified only by dropping unrelated
// small-stack/rand-callback branches that don't touch globalRNG/globalRNGMutex.
typedef struct wolfSSL_Mutex { int dummy; } wolfSSL_Mutex;
typedef struct WC_RNG {
    unsigned char seed[16];
    int drbg;
} WC_RNG;
#define WOLFSSL_SUCCESS 1
#define WOLFSSL_FAILURE 0
#define RNG_MAX_BLOCK_LEN 1024

extern int wc_LockMutex(wolfSSL_Mutex* m);
extern int wc_UnLockMutex(wolfSSL_Mutex* m);
extern int wc_RNG_GenerateBlock(WC_RNG* rng, unsigned char* buf, unsigned int sz);
extern int wc_GenerateSeed(unsigned char* seed, unsigned char* entropy, unsigned int sz);
extern int wc_RNG_DRBG_Reseed(WC_RNG* rng, unsigned char* entropy, unsigned int sz);
extern void WOLFSSL_ENTER(const char* s);
extern void WOLFSSL_MSG(const char* s);

static WC_RNG globalRNG;
static wolfSSL_Mutex globalRNGMutex;
static int initGlobalRNG = 1;

int wolfSSL_RAND_bytes(unsigned char* buf, int num)
{
    int ret = 0;
    WC_RNG* rng = NULL;
    int used_global = 0;

    WOLFSSL_ENTER("wolfSSL_RAND_bytes");
    if (buf == NULL || num < 0)
        return 0;

    if (initGlobalRNG) {
        if (wc_LockMutex(&globalRNGMutex) != 0) {
            WOLFSSL_MSG("Bad Lock Mutex rng");
            return ret;
        }
        if (initGlobalRNG) {
            rng = &globalRNG;
            used_global = 1;
        }
        else {
            wc_UnLockMutex(&globalRNGMutex);
        }
    }

    if (rng) {
        int blockCount = num / RNG_MAX_BLOCK_LEN;
        while (blockCount--) {
            ret = wc_RNG_GenerateBlock(rng, buf, RNG_MAX_BLOCK_LEN);
            if (ret != 0) {
                WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
                break;
            }
            num -= RNG_MAX_BLOCK_LEN;
            buf += RNG_MAX_BLOCK_LEN;
        }
        if (ret == 0 && num)
            ret = wc_RNG_GenerateBlock(rng, buf, (unsigned int)num);
        if (ret != 0)
            WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
        else
            ret = WOLFSSL_SUCCESS;
    }

    if (used_global == 1)
        wc_UnLockMutex(&globalRNGMutex);

    return ret;
}

int wolfSSL_RAND_poll(void)
{
    unsigned char entropy[16];
    int ret = 0;
    unsigned int entropy_sz = 16;

    WOLFSSL_ENTER("wolfSSL_RAND_poll");
    if (initGlobalRNG == 0) {
        WOLFSSL_MSG("Global RNG no Init");
        return WOLFSSL_FAILURE;
    }
    ret = wc_GenerateSeed(globalRNG.seed, entropy, entropy_sz);
    if (ret != 0) {
        WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
        ret = WOLFSSL_FAILURE;
    }
    else {
        ret = wc_RNG_DRBG_Reseed(&globalRNG, entropy, entropy_sz);
        if (ret != 0) {
            WOLFSSL_MSG("Error reseeding DRBG");
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }
    }

    return ret;
}
