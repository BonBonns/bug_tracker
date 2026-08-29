#include <string.h>
extern unsigned char TBL[256];

/* POS delegation wrapper: writes length arg n into dest param d (via memcpy). */
void deleg(char *d, const char *s, unsigned n) { memcpy(d, s, n); }

/* POS delegation with a local ALIAS of the dest param. */
void deleg_alias(char *d, const char *s, unsigned n) { char *p = d; memcpy(p, s, n); }

/* POS loop pointer-walk wrapper (ascii2ebcdic shape): writes count elems into dest. */
void walk(void *dest, const void *srce, unsigned count) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) *u++ = TBL[*v++];
}

/* NEG name-only: named like a copy but the body writes nothing of its params. */
void copy_into(char *d, const char *s, unsigned n) { return; }

/* NEG dest-not-param: the memcpy writes a LOCAL, nothing propagates to the caller dest. */
void writes_local(char *d, const char *s, unsigned n) { char tmp[8]; memcpy(tmp, s, n); }

/* NEG length-not-param: fixed constant length, not the length ARGUMENT. */
void fixed_len(char *d, const char *s, unsigned n) { memcpy(d, s, 4); }

/* NEG conflict: two sinks write the dest param with DIFFERENT lengths -> ambiguous. */
void conflict(char *d, const char *s, unsigned n, unsigned m) { memcpy(d, s, n); memmove(d, s, m); }

/* ARGUMENT POSITION: params in NON-standard order (dest is arg1, length is arg0). The
 * summary must bind dest_param_index=1, length_param_index=0 -- not assume memcpy's 0/2. */
void deleg_reordered(unsigned n, char *d, const char *s) { memcpy(d, s, n); }

void caller(const char *src, unsigned n) {
    char big[64];
    char small[16];
    deleg(big, src, 32);          /* literal 32 <= 64 -> deterministic_complete */
    deleg_alias(big, src, n);     /* symbolic n -> additional evidence / unresolved */
    deleg(small, src, 40);        /* literal 40 > 16 -> proven_oversized */
    walk(big, src, n);            /* recognized; symbolic n */
    copy_into(big, src, n);       /* NOT recognized (name only) */
    writes_local(big, src, n);    /* NOT recognized (dest not a param) */
    fixed_len(big, src, n);       /* NOT recognized (length not a param) */
    conflict(big, src, n, n);     /* NOT recognized (conflicting summary) */
    deleg_reordered(32, big, src);/* arg-position: dest=arg1, len=arg0 -> 32<=64 safe */
}
