// LOCK-SAFE-R01 development-site recovery: Dtls13RtxAddAck exactly as it appears at the
// real, vulnerable (pre-fix) wolfSSL commit 7efc962d047aa5590c7d844edad87e74aed833b5,
// fixed by CVE-2026-5264's commit 3034dd9e (case_e062ef20 in THREAD_SAFETY_R01.md).
// Function body copied verbatim from src/dtls13.c; only the surrounding type/decl stubs
// below are synthetic, so c2cpg can parse this file standalone.
typedef struct WOLFSSL WOLFSSL;
typedef struct w64wrapper { unsigned int hi, lo; } w64wrapper;
typedef struct Dtls13RecordNumber {
    w64wrapper epoch;
    w64wrapper seq;
    struct Dtls13RecordNumber* next;
} Dtls13RecordNumber;
typedef struct wolfSSL_Mutex { int dummy; } wolfSSL_Mutex;
struct WOLFSSL {
    struct {
        Dtls13RecordNumber* seenRecords;
        wolfSSL_Mutex mutex;
    } dtls13Rtx;
    void* heap;
};
#define MEMORY_E (-125)
#define WOLFSSL_RW_THREADED

extern int wc_LockMutex(wolfSSL_Mutex* m);
extern int wc_UnLockMutex(wolfSSL_Mutex* m);
extern int w64Equal(w64wrapper a, w64wrapper b);
extern int w64LT(w64wrapper a, w64wrapper b);
extern Dtls13RecordNumber* Dtls13NewRecordNumber(w64wrapper epoch, w64wrapper seq, void* heap);
extern void WOLFSSL_ENTER(const char* s);

int Dtls13RtxAddAck(WOLFSSL* ssl, w64wrapper epoch, w64wrapper seq)
{
    Dtls13RecordNumber* rn;

    WOLFSSL_ENTER("Dtls13RtxAddAck");

#ifdef WOLFSSL_RW_THREADED
    if (wc_LockMutex(&ssl->dtls13Rtx.mutex) == 0)
#endif
    {
        /* Find location to insert new record */
        Dtls13RecordNumber** prevNext = &ssl->dtls13Rtx.seenRecords;
        Dtls13RecordNumber* cur = ssl->dtls13Rtx.seenRecords;

        for (; cur != NULL; prevNext = &cur->next, cur = cur->next) {
            if (w64Equal(cur->epoch, epoch) && w64Equal(cur->seq, seq)) {
                /* already in list. no duplicates. */
    #ifdef WOLFSSL_RW_THREADED
                wc_UnLockMutex(&ssl->dtls13Rtx.mutex);
    #endif
                return 0;
            }
            else if (w64LT(epoch, cur->epoch)
                    || (w64Equal(epoch, cur->epoch)
                            && w64LT(seq, cur->seq))) {
                break;
            }
        }

        rn = Dtls13NewRecordNumber(epoch, seq, ssl->heap);
        if (rn == NULL) {
    #ifdef WOLFSSL_RW_THREADED
            wc_UnLockMutex(&ssl->dtls13Rtx.mutex);
    #endif
            return MEMORY_E;
        }

        *prevNext = rn;
        rn->next = cur;
    #ifdef WOLFSSL_RW_THREADED
        wc_UnLockMutex(&ssl->dtls13Rtx.mutex);
    #endif
    }

    return 0;
}
