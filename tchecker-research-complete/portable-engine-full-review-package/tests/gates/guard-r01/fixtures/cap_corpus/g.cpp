// GUARD-R01 / task #42: real, committed source for the OOB_WRITE/OOB_READ control corpus that
// /tmp/cap_corpus used to be built from (operator-maintained, uncommitted, lost -- see
// FIXTURE_NOTE.md). Every function name here is referenced directly by oob_write_controls.py /
// oob_read_controls.py's own real assertions. See build_cap_corpus.sh for how this is compiled
// into the fact documents those assertions read.
#include <cstddef>
#include <cstdio>
#include <cstring>

// g_write_ok / g_write_lt: correctly bounded writes (LE / LT relation) -- must NOT be OOB_WRITE
// candidates. Neither has a resolvable read-side capacity (src is a pointer parameter, not a
// fixed local array), so neither can be an OOB_READ candidate either.
void g_write_ok(const char *src, size_t n) {
    char buf[64];
    if (n <= sizeof(buf)) {
        memcpy(buf, src, n);
    }
}

void g_write_lt(const char *src, size_t n) {
    char buf[64];
    if (n < sizeof(buf)) {
        memcpy(buf, src, n);
    }
}

// nc_b1: no guard at all -- a real, unambiguous OOB_WRITE candidate.
void nc_b1(const char *src, size_t n) {
    char buf[32];
    memcpy(buf, src, n);
}

// nc_b3: same shape as nc_b1, via strncpy instead of memcpy -- exercises a second real
// WRITE_DEST/READ_SRC/EXTENT call name.
void nc_b3(const char *src, size_t n) {
    char buf[24];
    strncpy(buf, src, n);
}

// nc_b4: a reject-guard shape (if (n > sizeof(buf)) ...) whose branch does NOT terminate (no
// `return` anywhere in this function) -- the normalizer's own CPP_REJECT_GUARD_BOUND rule
// requires the guarded function to have a real return reachable from the reject branch before
// accepting the surviving-path bound; a non-terminating guard must NOT establish one. Still a
// real OOB_WRITE candidate.
static int g_sink;
void nc_b4(const char *src, size_t n) {
    char buf[40];
    if (n > sizeof(buf)) {
        g_sink = 1;  // logged, but the guard does not return -- falls through regardless
    }
    memcpy(buf, src, n);
}

// nc_b5: "wrong-expr guard" -- a real guard exists, but its RHS names a DIFFERENT buffer's
// capacity (`other`, 8 bytes) than the one actually written (`buf`, 64 bytes). The normalizer's
// bound derivation requires the guard's RHS to name the EXACT written storage's own capacity;
// this does not, so no bound attaches. Real OOB_WRITE candidate -- the guard's mere presence
// must not suppress it.
void nc_b5(const char *src, size_t n) {
    char buf[64];
    char other[8];
    if (n <= sizeof(other)) {
        memcpy(buf, src, n);
    }
}

// nc_b6: the write's own destination (dst_buf) has NO bound at all, but the READ side
// (local_src) legitimately does. Proves OOB_WRITE isolation: a real SOURCE_CAPACITY bound
// elsewhere in the corpus must never suppress an unrelated, unguarded WRITE_DEST candidate.
void nc_b6(size_t n) {
    char dst_buf[64];
    char local_src[8];
    if (n <= sizeof(local_src)) {
        memcpy(dst_buf, local_src, n);
    }
}

// g_read_ok: correctly source-bounded read (NC-R6) -- must NOT be an OOB_READ candidate. dst is
// a pointer parameter (no resolvable dest capacity), so this can never be an OOB_WRITE candidate
// either.
void g_read_ok(char *dst, size_t n) {
    char local_src[16];
    if (n <= sizeof(local_src)) {
        memcpy(dst, local_src, n);
    }
}

// mix_fixed: the corpus's one real OOB_READ candidate. dst is a pointer parameter (dest
// capacity unresolvable, so this can never be an OOB_WRITE candidate -- the "mix": its write
// side is unresolvable/moot while its read side is a real, unguarded fixed-array source).
void mix_fixed(char *dst, size_t n) {
    char local_src[8];
    memcpy(dst, local_src, n);
}
