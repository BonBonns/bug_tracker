// case_a6eb1f6d vulnerable revision (2d892f07): full wolfSSL_RAND_bytes BEFORE the
// PID-reseed fix -- verifying it's already lock-balanced on globalRNGMutex (the real bug
// is a missing FIPS reseed-on-fork check, unrelated to lock balance).
typedef struct wolfSSL_Mutex { int dummy; } wolfSSL_Mutex;
typedef struct WC_RNG { unsigned char seed[16]; } WC_RNG;
#define WOLFSSL_SUCCESS 1
#define RNG_MAX_BLOCK_LEN 1024
#define DYNAMIC_TYPE_RNG 22

extern int wc_LockMutex(wolfSSL_Mutex* m);
extern int wc_UnLockMutex(wolfSSL_Mutex* m);
extern int wc_InitRng(WC_RNG* rng);
extern void wc_FreeRng(WC_RNG* rng);
extern int wc_RNG_GenerateBlock(WC_RNG* rng, unsigned char* buf, unsigned int sz);
extern void* XMALLOC(unsigned long sz, void* heap, int type);
extern void XFREE(void* p, void* heap, int type);
extern void WOLFSSL_ENTER(const char* s);
extern void WOLFSSL_MSG(const char* s);
extern int wolfSSL_RAND_InitMutex(void);

static WC_RNG globalRNG;
static wolfSSL_Mutex globalRNGMutex;
static wolfSSL_Mutex gRandMethodMutex;
static int initGlobalRNG = 1;

typedef struct { int (*bytes)(unsigned char*, int); } RandMethods;
static RandMethods* gRandMethods = 0;

int wolfSSL_RAND_bytes(unsigned char* buf, int num)
{
    int     ret = 0;
    WC_RNG* rng = NULL;
    WC_RNG* tmpRNG = NULL;
    int initTmpRng = 0;
    int used_global = 0;

    WOLFSSL_ENTER("wolfSSL_RAND_bytes");
    if (buf == NULL || num < 0)
        return 0;

    if (wolfSSL_RAND_InitMutex() == 0 && wc_LockMutex(&gRandMethodMutex) == 0) {
        if (gRandMethods && gRandMethods->bytes) {
            ret = gRandMethods->bytes(buf, num);
            wc_UnLockMutex(&gRandMethodMutex);
            return ret;
        }
        wc_UnLockMutex(&gRandMethodMutex);
    }

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

    if (used_global == 0)
    {
        tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        if (tmpRNG == NULL)
            return ret;
        if (wc_InitRng(tmpRNG) == 0) {
            rng = tmpRNG;
            initTmpRng = 1;
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
    if (initTmpRng)
        wc_FreeRng(tmpRNG);
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);

    return ret;
}
