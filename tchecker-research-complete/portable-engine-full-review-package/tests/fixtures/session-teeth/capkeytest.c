#include <stdint.h>
#include <string.h>
#include <stddef.h>
struct A { char digest[20]; };
struct B { char nonce[32]; };
struct S { char a[16]; char b[64]; };

void f(struct A *a, struct B *b, char *x, char *y, size_t nx, size_t ny) {
    memcpy(a->digest, x, nx);   /* FIELD key A::digest, cap 20 */
    memcpy(b->nonce,  y, ny);   /* FIELD key B::nonce,  cap 32 */
}
/* reversed order — must give identical result (catches last-write-wins) */
void g(struct B *b, struct A *a, char *y, char *x, size_t ny, size_t nx) {
    memcpy(b->nonce,  y, ny);
    memcpy(a->digest, x, nx);
}
/* two dimensions of identity */
void h(struct S *x, struct S *y, char *src, size_t n) {
    memcpy(x->a, src, n);   /* x->a cap 16 */
    memcpy(x->b, src, n);   /* x->b cap 64 — same base diff member */
    memcpy(y->a, src, n);   /* y->a cap 16 — diff base same member */
}
int main(void){return 0;}
