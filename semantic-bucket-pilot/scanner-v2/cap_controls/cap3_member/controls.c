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

/* ITERATION COUNT #1 -- `i = 0; i <= 256` OFF-BY-ONE. The bound TOKEN 256 equals the
 * capacity, but `<=` performs 257 writes (indices 0..256) -> proven_oversized. A detector
 * that trusts the bound token instead of the iteration count would wrongly call this safe. */
void mw_le256(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal; i <= 256; i++, pp++) { pp->red = s[i]; }
}

/* ITERATION COUNT #2 -- NONZERO INIT. `i = 1; i <= 256; i++` performs 256 writes (indices
 * 0..255 through the cursor) -> fits capacity 256 exactly. The bound token alone (256) is
 * insufficient; the init (1) and the `<=` together yield exactly 256. */
void mw_init1(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 1, pp = pal; i <= 256; i++, pp++) { pp->red = s[i - 1]; }
}

/* ITERATION COUNT #3 -- DECREMENTING counter. `i = 256; i > 0; i--` performs 256 writes
 * -> fits capacity 256. The simulation must handle a `>` comparison with a negative step. */
void mw_dec(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 256, pp = pal; i > 0; i--, pp++) { pp->red = s[i - 1]; }
}

/* ITERATION COUNT #4 -- STEP `i += 2`. `i = 0; i < 256; i += 2` performs 128 iterations,
 * so the once-per-iteration cursor advances 128 times -> 128 writes -> fits. A detector that
 * assumed step 1 (256 writes) would be wrong; the literal step must drive the count. */
void mw_step2(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal; i < 256; i += 2, pp++) { pp->red = s[i]; }
}

/* ITERATION COUNT #5 -- counter MODIFIED IN THE BODY. Literal init/bound/step, but the body
 * also mutates the counter, so the header alone does not determine the count -> conservative
 * open_candidate (bound_shape=counter_modified_in_body), never a false safe. */
void mw_bodymod(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp; int i;
    for (i = 0, pp = pal; i < 256; i++, pp++) { pp->red = s[i]; i++; }
}

/* ITERATION COUNT #6 -- cursor initialized as `array + offset`. Start offset 100, 200 writes
 * -> reaches index 299 >= capacity 256 -> proven_oversized. A detector ignoring the cursor's
 * starting offset would compute 200 <= 256 and wrongly call this safe. */
void mw_offset(const unsigned char *s) {
    struct rgb pal[256]; struct rgb *pp = pal + 100; int i;
    for (i = 0; i < 200; i++, pp++) { pp->red = s[i]; }
}
