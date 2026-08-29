#include <string.h>
typedef unsigned int uint;

/* NEG-guard: real dominating, controlling guard proving headerLen >= mdBlockSize,
   matching hmacct.c's real shape -- must be credited deterministic_complete. */
void guarded(char *dst, char *src, uint headerLen, uint mdBlockSize) {
    if (headerLen < mdBlockSize) {
        return;
    }
    uint overhang = headerLen - mdBlockSize;
    memcpy(dst, src, overhang);
}

/* No guard at all -- must be open_candidate. */
void unguarded(char *dst, char *src, uint headerLen, uint mdBlockSize) {
    uint overhang = headerLen - mdBlockSize;
    memcpy(dst, src, overhang);
}

/* Guard exists but on the WRONG operand pair -- must be open_candidate, not
   falsely credited. */
void wrongpair(char *dst, char *src, uint headerLen, uint mdBlockSize, uint other) {
    if (other < mdBlockSize) {
        return;
    }
    uint overhang = headerLen - mdBlockSize;
    memcpy(dst, src, overhang);
}

/* Compound-adjustment guard -- deliberately never credited (unproven adjustment
   safety), must be open_candidate. */
void compoundguard(char *dst, char *src, uint headerLen, uint mdBlockSize) {
    if (headerLen - 4 < mdBlockSize) {
        return;
    }
    uint overhang = headerLen - mdBlockSize;
    memcpy(dst, src, overhang);
}

/* Direct inline subtraction (no intervening local) into a sink width arg,
   with a real guard -- credited. */
void directguard(char *dst, char *src, uint headerLen, uint mdBlockSize) {
    if (headerLen < mdBlockSize) {
        return;
    }
    memcpy(dst, src, headerLen - mdBlockSize);
}

/* Subtraction feeding an array index, no guard -- open_candidate. */
void idxunguarded(char *dst, uint a, uint b) {
    char buf[64];
    dst[0] = buf[a - b];
}

/* Subtraction feeding an array index, guarded -- credited. */
void idxguarded(char *dst, uint a, uint b) {
    char buf[64];
    if (a < b) {
        return;
    }
    dst[0] = buf[a - b];
}

/* Guard controls the call but is assert-only -- compiled out in release,
   must NOT be credited. */
void assertonly(char *dst, char *src, uint headerLen, uint mdBlockSize) {
    assert(headerLen >= mdBlockSize);
    uint overhang = headerLen - mdBlockSize;
    memcpy(dst, src, overhang);
}
