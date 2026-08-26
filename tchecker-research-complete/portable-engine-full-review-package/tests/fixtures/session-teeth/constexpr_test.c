#include <stdint.h>
#include <string.h>
#include <stddef.h>
#define A 32
#define B (A - 4)
enum { C = 64, D = 128 };

struct X {
    char a[A];      /* macro literal -> 32 */
    char b[B];      /* macro expr -> 28 */
    char c[C];      /* enum -> 64 */
    char d[D];      /* enum -> 128 */
    char lit[16];   /* plain literal -> 16 (control) */
};

#define GOOD 32
extern size_t runtime_n(void);
struct Y { char a[GOOD]; };
void f(struct Y *y, char *src) {
    memcpy(y->a, src, runtime_n());   /* runtime extent, must NOT be constrained */
}
int main(void){ struct X x; (void)x; return 0; }
