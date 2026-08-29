#include <stdlib.h>
void a5_heap(const char *s, unsigned n) {
    char *p = (char*)malloc(256); char *w = p;
    while (n-- != 0) *w++ = *s++;
}
