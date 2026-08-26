#include <stdint.h>
#include <string.h>
struct A { char reply[16]; };
struct B { char reply[64]; };
struct C { char fixed[32]; char *dynamic; };
struct S { char a[16]; char b[64]; };
extern uint16_t wire(void);

void f(struct A *a, struct B *b, char *src, size_t n) {
    memcpy(a->reply, src, n);   /* CAP-FID-1: dest cap 16 */
    memcpy(b->reply, src, n);   /* CAP-FID-2: dest cap 64 (no crossover from A::reply) */
}
void g(struct C *c, char *src, size_t n) {
    memcpy(c->fixed, src, n);   /* CAP-FID-4: fixed -> 32 */
    memcpy(c->dynamic, src, n); /* CAP-FID-5: dynamic -> UNKNOWN (pointer member) */
}
void h(struct S *x, char *src, size_t n) {
    memcpy(x->a, src, n);   /* -> 16 */
    memcpy(x->b, src, n);   /* -> 64, no borrowing from x->a */
}
int main(void){return 0;}
