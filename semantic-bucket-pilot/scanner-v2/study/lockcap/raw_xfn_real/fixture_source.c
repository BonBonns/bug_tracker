// LOCK-SAFE-R02 investigation: both real wolfSSL functions from the SAME file at the
// SAME vulnerable commit (3034dd9e) -- Dtls13RtxAddAck (locks ssl->dtls13Rtx.mutex around
// ssl->dtls13Rtx.seenRecords) and Dtls13RtxRemoveCurAck (touches the SAME seenRecords list,
// with NO lock at all -- the real bug fixed by case_644b3e3c). Bodies copied verbatim.
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
    struct { w64wrapper curEpoch64; w64wrapper curSeq; } keys;
    void* heap;
};
#define MEMORY_E (-125)
#define DYNAMIC_TYPE_DTLS_MSG 100
#define WOLFSSL_RW_THREADED

extern int wc_LockMutex(wolfSSL_Mutex* m);
extern int wc_UnLockMutex(wolfSSL_Mutex* m);
extern int w64Equal(w64wrapper a, w64wrapper b);
extern int w64LT(w64wrapper a, w64wrapper b);
extern Dtls13RecordNumber* Dtls13NewRecordNumber(w64wrapper epoch, w64wrapper seq, void* heap);
extern void WOLFSSL_ENTER(const char* s);
extern void XFREE(void* p, void* heap, int type);

int Dtls13RtxAddAck(WOLFSSL* ssl, w64wrapper epoch, w64wrapper seq)
{
    Dtls13RecordNumber* rn;

    WOLFSSL_ENTER("Dtls13RtxAddAck");

#ifdef WOLFSSL_RW_THREADED
    if (wc_LockMutex(&ssl->dtls13Rtx.mutex) == 0)
#endif
    {
        Dtls13RecordNumber** prevNext = &ssl->dtls13Rtx.seenRecords;
        Dtls13RecordNumber* cur = ssl->dtls13Rtx.seenRecords;

        for (; cur != NULL; prevNext = &cur->next, cur = cur->next) {
            if (w64Equal(cur->epoch, epoch) && w64Equal(cur->seq, seq)) {
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

static void Dtls13RtxRemoveCurAck(WOLFSSL* ssl)
{
    Dtls13RecordNumber *rn, **prevNext;

    prevNext = &ssl->dtls13Rtx.seenRecords;
    rn = ssl->dtls13Rtx.seenRecords;

    while (rn != NULL) {
        if (w64Equal(rn->epoch, ssl->keys.curEpoch64) &&
            w64Equal(rn->seq, ssl->keys.curSeq)) {
            *prevNext = rn->next;
            XFREE(rn, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
            return;
        }

        prevNext = &rn->next;
        rn = rn->next;
    }
}
