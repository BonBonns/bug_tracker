// case_267d5a93 vulnerable revision (50f28d907): Dtls13RtxAddAck BEFORE the
// DTLS13_MAX_ACK_RECORDS capacity fix -- verifying it's already lock-balanced (a capacity
// bug, not a lock-safety bug).
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
        unsigned int seenRecordsCount;
        wolfSSL_Mutex mutex;
    } dtls13Rtx;
    void* heap;
};
#define MEMORY_E (-125)
#define DTLS13_ACK_MAX_RECORDS 512
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
        Dtls13RecordNumber** prevNext = &ssl->dtls13Rtx.seenRecords;
        Dtls13RecordNumber* cur = ssl->dtls13Rtx.seenRecords;

        if (ssl->dtls13Rtx.seenRecordsCount >= DTLS13_ACK_MAX_RECORDS) {
    #ifdef WOLFSSL_RW_THREADED
            wc_UnLockMutex(&ssl->dtls13Rtx.mutex);
    #endif
            return 0; /* list full, silently drop */
        }

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
