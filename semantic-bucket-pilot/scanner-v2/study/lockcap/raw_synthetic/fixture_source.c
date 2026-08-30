// LOCK-SAFE-R01 fixture: missing-unlock-before-return controls.
// wc_LockMutex/wc_UnLockMutex signatures match wolfSSL's real wrapper API
// (confirmed in THREAD_SAFETY_R01.md), declared here so c2cpg can parse this
// file standalone without the full wolfSSL header tree.
typedef struct wolfSSL_Mutex { int dummy; } wolfSSL_Mutex;
extern int wc_LockMutex(wolfSSL_Mutex* m);
extern int wc_UnLockMutex(wolfSSL_Mutex* m);
extern int some_unregistered_lock(wolfSSL_Mutex* m);
extern int some_unregistered_unlock(wolfSSL_Mutex* m);

// 1. VULNERABLE: lock acquired, but one early-return path skips the unlock.
int vulnMissingUnlock(wolfSSL_Mutex* mutex, int cond, int* out) {
    int ret = 0;
    if (wc_LockMutex(mutex) != 0) {
        return -1;
    }
    if (cond) {
        /* BUG: returns without releasing mutex */
        return -2;
    }
    *out = 1;
    wc_UnLockMutex(mutex);
    return ret;
}

// 2. FIXED: same shape, unlock added on the previously-missing path.
int fixedMissingUnlock(wolfSSL_Mutex* mutex, int cond, int* out) {
    int ret = 0;
    if (wc_LockMutex(mutex) != 0) {
        return -1;
    }
    if (cond) {
        wc_UnLockMutex(mutex);
        return -2;
    }
    *out = 1;
    wc_UnLockMutex(mutex);
    return ret;
}

// 3. NEGATIVE CONTROL: no lock/unlock calls at all -- must not flag.
int negNoLock(int cond, int* out) {
    if (cond) {
        return -1;
    }
    *out = 1;
    return 0;
}

// 4. NEGATIVE CONTROL: lock/unlock balanced on every exit path -- must not flag.
int negBalanced(wolfSSL_Mutex* mutex, int cond, int* out) {
    int ret = 0;
    if (wc_LockMutex(mutex) != 0) {
        return -1;
    }
    if (cond) {
        wc_UnLockMutex(mutex);
        return -2;
    }
    *out = 1;
    wc_UnLockMutex(mutex);
    return ret;
}

// 5. NEGATIVE CONTROL (ambiguity): two DIFFERENT lock objects in one function --
// capability must track each independently (both actually balanced here), never
// conflate the two into one false "leak".
int negTwoObjectsBalanced(wolfSSL_Mutex* mutexA, wolfSSL_Mutex* mutexB, int cond, int* out) {
    if (wc_LockMutex(mutexA) != 0) {
        return -1;
    }
    if (wc_LockMutex(mutexB) != 0) {
        wc_UnLockMutex(mutexA);
        return -2;
    }
    if (cond) {
        wc_UnLockMutex(mutexB);
        wc_UnLockMutex(mutexA);
        return -3;
    }
    *out = 1;
    wc_UnLockMutex(mutexB);
    wc_UnLockMutex(mutexA);
    return 0;
}

// 6. NEGATIVE CONTROL: an unregistered lock-family name -- proves the capability's
// LOCK_FUNCS/UNLOCK_FUNCS table is load-bearing (same negative-control pattern as
// PORT_Memcpy_NOT_REGISTERED elsewhere in this project). Same missing-release shape
// as case 1, but must NOT be recognized since the function name isn't registered.
int negUnregisteredLockName(wolfSSL_Mutex* mutex, int cond, int* out) {
    int ret = 0;
    if (some_unregistered_lock(mutex) != 0) {
        return -1;
    }
    if (cond) {
        return -2;
    }
    *out = 1;
    some_unregistered_unlock(mutex);
    return ret;
}
