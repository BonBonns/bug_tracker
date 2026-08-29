#include <string.h>
extern unsigned char TBL[256];

/* POS canonical counted writer (ascii2ebcdic shape): unsigned count, single advance. */
void cw(void *dest, const void *srce, unsigned count) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) *u++ = TBL[*v++];
}

/* SIGNEDNESS: signed counter -> may be negative; call-site must not prove a bound. */
void cw_signed(void *dest, const void *srce, int count) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) *u++ = TBL[*v++];
}

/* POINTER ADVANCEMENT: single-slot write (no advance) -> extent 1, NOT count. No summary. */
void no_advance(char *dest, char s, unsigned count) {
    char *u = dest;
    while (count-- != 0) *u = s;
}

/* ADVANCEMENT MULTIPLICITY: two advances per iter -> extent 2*count. Must abstain. */
void double_advance(char *dest, const char *srce, unsigned count) {
    char *u = dest; const char *v = srce;
    while (count-- != 0) { *u++ = *v++; *u++ = 0; }
}

/* ALIAS IDENTITY: the advancing pointer is an UNRELATED local, not the dest param. */
void alien_walk(char *dest, unsigned count) {
    char local[8]; char *u = local;
    while (count-- != 0) *u++ = 0;
}

/* CONFLICTING PATHS: two different dest params walked under the same counter -> abstain. */
void two_dests(char *a, char *b, const char *srce, unsigned count) {
    char *ua = a; char *ub = b; const char *v = srce;
    while (count-- != 0) { *ua++ = *v; *ub++ = *v; }
}

/* ARGUMENT POSITION: params in NON-standard order (dest is arg1, counter is arg0). */
void cw_reordered(unsigned count, void *dest, const void *srce) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) *u++ = TBL[*v++];
}

/* EARLY EXIT: a break inside the loop writes FEWER than count; count stays a sound upper
 * bound, so the summary is still emitted (single advance, one counter). */
void cw_break(void *dest, const void *srce, unsigned count) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) { if (*v == 0) break; *u++ = TBL[*v++]; }
}

void caller(const char *src, unsigned n, int sn) {
    char big[64];
    char small[16];
    cw(big, src, 32);        /* literal 32 <= 64 -> deterministic_complete */
    cw(small, src, 40);      /* literal 40 > 16 -> proven_oversized */
    cw(big, src, 0);         /* ZERO COUNT literal -> proven safe */
    cw(big, src, n);         /* unsigned symbolic -> count_bound_not_established */
    cw_signed(big, src, sn); /* SIGNED symbolic -> count_sign_unresolved (no false safe) */
    cw_reordered(16, big, src); /* arg-position: dest=arg1, counter=arg0 -> 16<=64 safe */
    cw_break(big, src, 20);  /* EARLY EXIT: still summarized; 20<=64 upper-bound safe */
}
