#include <stdint.h>
#include <string.h>
#include <stddef.h>
struct S { char a[16]; char b[64]; };
struct P { char fixed[32]; char *dynamic; };

void f(struct S *x, struct S *y, char *src, size_t n) {
    memcpy(x->a, src, n);   /* (storage(x), decl(a)) */
    memcpy(x->b, src, n);   /* (storage(x), decl(b)) — differs from x->a by member */
    memcpy(y->a, src, n);   /* (storage(y), decl(a)) — differs from x->a by base */
}
void g(struct S *x, char *src, size_t n) {
    struct S *z = x;
    memcpy(z->a, src, n);   /* unify with x->a ONLY if alias machinery proves z==x */
}
void h(struct P *p, char *src, size_t n) {
    memcpy(p->fixed, src, n);    /* fixed[32] -> capacity resolvable */
    memcpy(p->dynamic, src, n);  /* char* -> capacity must stay UNKNOWN */
}
void k(struct S *arr, int i, char *src, size_t n) {
    memcpy(arr[i].a, src, n);   /* base-element identity — abstain if not established */
}
int main(void){return 0;}
