// Minimal SYNTHETIC fixture (not from any real historical CVE or npm package), built only to
// exercise lock_balance_verdict.py's own explicit LOCK_NO_OBJECT_ARG abstention path: a
// recognized lock primitive called with no resolvable object argument at all. Disclosed as
// synthetic in the pilot's own report -- LOCK_BALANCE's positive and confirmed-negative paths
// both come from the real, committed wolfSSL fixture; only this abstention exemplar is
// hand-built, because no real historical fixture or npm candidate exercising it was found.
extern int pthread_mutex_lock();

int no_object_arg_example(int flag) {
    pthread_mutex_lock();
    if (flag)
        return 1;
    return 0;
}
