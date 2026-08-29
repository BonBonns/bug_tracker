#include <stdlib.h>
struct rgb { unsigned char red, green, blue; };

/* POSITIVE: PNG003-shape, for-update advance, static array, symbolic UNGUARDED bound. */
void mw_open(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal; i < n; i++, pp++) {
        pp->red = s[3*i]; pp->green = s[3*i+1]; pp->blue = s[3*i+2];
    }
}

/* GUARDED: a visible clamp on the loop bound -> capacity-bounded. */
void mw_guarded(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp; int i;
    if (n > 256) n = 256;
    for (i = 0, pp = pal; i < n; i++, pp++) {
        pp->red = s[3*i]; pp->green = s[3*i+1]; pp->blue = s[3*i+2];
    }
}

/* LITERAL FITS: bound 100 <= capacity 256. */
void mw_fits(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal; i < 100; i++, pp++) { pp->red = s[i]; }
}

/* LITERAL OVER: bound 300 > capacity 256 -> proven oversized. */
void mw_over(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal; i < 300; i++, pp++) { pp->red = s[i]; }
}

/* CONDITIONAL INCREMENT (body advance, per-iteration not provable). */
void mw_cond(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp = pal; int i;
    for (i = 0; i < n; i++) {
        pp->red = s[i];
        if (s[i]) pp++;
    }
}

/* MULTIPLE INCREMENTS (two advance sites). */
void mw_multi(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp = pal; int i;
    for (i = 0; i < n; i++) { pp->red = s[i]; pp++; pp++; }
}

/* POINTER RESET (re-based to the same base mid-walk). */
void mw_reset(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp = pal; int i;
    for (i = 0; i < n; i++, pp++) { pp->red = s[i]; }
    pp = pal;
    for (i = 0; i < n; i++, pp++) { pp->green = s[i]; }
}

/* ALIAS CONFLICT (base bound from two distinct arrays). */
void mw_alias(const unsigned char *s, int n) {
    struct rgb a[256]; struct rgb b[256]; struct rgb *pp = a; int i;
    pp = b;
    for (i = 0; i < n; i++, pp++) { pp->red = s[i]; }
}

/* ONE-PAST (body advance BEFORE the member write, on distinct lines). */
void mw_onepast(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp = pal; int i;
    for (i = 0; i < n; i++) {
        pp++;
        pp->red = s[i];
    }
}

/* EARLY EXIT (for-update advance + break): count stays an upper bound -> open candidate. */
void mw_break(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal; i < n; i++, pp++) { pp->red = s[i]; if (s[i] == 0) break; }
}

/* UNKNOWN LIFETIME / PARAMETER BASE (caller-supplied pointer, no local extent). */
void mw_param(struct rgb *pp, const unsigned char *s, int n) {
    int i;
    for (i = 0; i < n; i++, pp++) { pp->red = s[i]; }
}

/* NEGATIVE: a non-advancing single struct-member write (NOT a walk) -> no cap3 op. */
void mw_single(struct rgb *pp, unsigned char v) { pp->red = v; }

/* NEGATIVE: a byte *p++ deref walk (cursor-producer domain) -> no cap3 op. */
void mw_byte(const char *s, int n) {
    char buf[64]; char *p = buf;
    while (n-- != 0) *p++ = *s++;
}

/* MULTILINE for-header (for-update advance split across lines). AST membership must
 * recognize the update advance regardless of line layout. */
void mw_multiline(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal;
         i < n;
         i++, pp++)
    {
        pp->red = s[3*i]; pp->green = s[3*i+1]; pp->blue = s[3*i+2];
    }
}

/* SAME-LINE body increment: a BODY increment written on the header's line. The old
 * line-coincidence heuristic would misread this as a for-update; AST membership must place
 * it in the BODY (not the update) and abstain. */
void mw_sameline(const unsigned char *s, int n) {
    struct rgb pal[256]; struct rgb *pp = pal; int i;
    for (i = 0; i < n; i++) { pp++; pp->red = s[i]; }
}
