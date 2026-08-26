#include <stdint.h>
#include <string.h>
struct A { char reply[16]; char unique_a[8]; };
struct B { char reply[64]; };
typedef struct A A_t;
extern void use(void *);

void test(struct A *a, struct B *b) {
    use(a->reply);       /* -> A::reply (decl in struct A) */
    use(b->reply);       /* -> B::reply (decl in struct B) */
    use(a->unique_a);    /* -> A::unique_a (globally unique too) */
}
void td(A_t *a) {
    use(a->reply);       /* typedef base: A_t -> struct A; support only if type facts allow */
}
int main(void){return 0;}
