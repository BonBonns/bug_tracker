// LOCK-SAFE-R02 synthetic controls: protected-field inference, complementing the real
// xfn_probe.c positive-recovery evidence.
typedef struct wolfSSL_Mutex { int dummy; } wolfSSL_Mutex;
extern int wc_LockMutex(wolfSSL_Mutex* m);
extern int wc_UnLockMutex(wolfSSL_Mutex* m);

typedef struct Ctx {
    struct { int fieldX; wolfSSL_Mutex mutexA; } grpA;
    struct { int fieldY; } grpB;                       // never touched under any lock
    struct { int fieldZ; wolfSSL_Mutex mutexC1; wolfSSL_Mutex mutexC2; } grpC;
} Ctx;

// 1. NEGATIVE CONTROL: fieldX is consistently protected everywhere it's touched.
int consistentA1(Ctx* c) {
    int v;
    if (wc_LockMutex(&c->grpA.mutexA) != 0)
        return -1;
    v = c->grpA.fieldX;
    wc_UnLockMutex(&c->grpA.mutexA);
    return v;
}

int consistentA2(Ctx* c, int nv) {
    if (wc_LockMutex(&c->grpA.mutexA) != 0)
        return -1;
    c->grpA.fieldX = nv;
    wc_UnLockMutex(&c->grpA.mutexA);
    return 0;
}

// 2. NEGATIVE CONTROL: fieldY is never touched under any lock anywhere -- no pattern to
// infer, must never be flagged (no evidence, no guess).
int neverLocked(Ctx* c) {
    return c->grpB.fieldY;
}

// 3. NEGATIVE CONTROL (ambiguity): fieldZ is protected by TWO DIFFERENT locks in two
// different functions -- conflicting evidence, must abstain for fieldZ entirely (neither
// access flagged, both left alone).
int ambiguousC1(Ctx* c) {
    int v;
    if (wc_LockMutex(&c->grpC.mutexC1) != 0)
        return -1;
    v = c->grpC.fieldZ;
    wc_UnLockMutex(&c->grpC.mutexC1);
    return v;
}

int ambiguousC2(Ctx* c) {
    int v;
    if (wc_LockMutex(&c->grpC.mutexC2) != 0)
        return -1;
    v = c->grpC.fieldZ;
    wc_UnLockMutex(&c->grpC.mutexC2);
    return v;
}
