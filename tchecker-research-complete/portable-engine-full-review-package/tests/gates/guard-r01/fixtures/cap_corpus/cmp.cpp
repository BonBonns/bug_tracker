// GUARD-R01 / task #33: OOB_COMPARE positive/negative control corpus. Exercises the class-
// separation invariant (a capacity bound for side A must NOT certify side B; safety requires
// n<=cap(A) AND n<=cap(B)), both real-bug shapes the narrow, compile-time-constant-extent-only
// design CAN catch, and the real-world shapes (variable extent, pointer operand) that dominate
// this corpus's own actual memcmp/strncmp usage (see the task #33 corpus survey) and correctly
// make the reader abstain.
#include <cstddef>
#include <cstring>

// cmp_safe: both sides real fixed arrays, extent is a literal exactly matching both capacities
// -- two-sided safe, must NOT be a candidate.
bool cmp_safe() {
    char a[16];
    char b[16];
    return memcmp(a, b, 16) == 0;
}

// cmp_overrun_b: extent (16) exceeds side B's real capacity (8) -- a real OOB_COMPARE
// candidate, overruns=['B'].
bool cmp_overrun_b() {
    char a[32];
    char b[8];
    return memcmp(a, b, 16) == 0;
}

// cmp_overrun_sizeof: the classic real "wrong sizeof" bug -- the extent is sizeof(b) (64), but
// the OTHER operand, a, is only 8 bytes. A real, realistic shape: a developer copy-pasted a
// comparison and updated one buffer's name but not the sizeof() argument. overruns=['A'].
bool cmp_overrun_sizeof() {
    char a[8];
    char b[64];
    return memcmp(a, b, sizeof(b)) == 0;
}

// cmp_abstain_var: extent is a real variable (n), not a compile-time constant -- must ABSTAIN,
// even though side B's real capacity (8) is smaller than side A's (32) and n could exceed it at
// runtime. This is the dominant real shape in this project's own corpus survey (task #33):
// memcmp(a->metadata, b->metadata, a->metadata_size)-style variable-length comparisons.
bool cmp_abstain_var(size_t n) {
    char a[32];
    char b[8];
    return memcmp(a, b, n) == 0;
}

// cmp_abstain_pointer: side B is a pointer parameter, not a resolvable fixed-array capacity --
// must ABSTAIN (unresolved capacity), even with a literal extent. The dominant real shape for
// memcmp(buf, "string literal", N) and memcmp(buf, some_pointer_param, N) in this project's own
// corpus survey.
bool cmp_abstain_pointer(const char *p) {
    char a[8];
    return memcmp(a, p, 8) == 0;
}
