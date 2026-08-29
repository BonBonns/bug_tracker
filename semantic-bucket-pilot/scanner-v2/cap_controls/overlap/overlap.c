#include <string.h>
extern unsigned char TBL[256];

/* G: a counted-writer callee whose body is IN SCOPE. Its physical pointer-walk write is
 * on the line marked below. cap3 (direct) recognizes THIS site; cap2 (counted-writer
 * summary) attributes G's effect at F's call site. Same underlying write. */
void g_writer(void *dest, const void *srce, unsigned count) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) *u++ = TBL[*v++];   /* <-- the one physical write in g_writer */
}

/* F: calls G. cap2 produces a call-site summary op here; its underlying_write points back
 * to g_writer's physical write line. */
void f_caller(const char *src, unsigned n) {
    char buf[64];
    g_writer(buf, src, n);
}
