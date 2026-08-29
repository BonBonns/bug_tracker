#include <stdlib.h>
#include <string.h>
struct S { char buf[16]; };

/* MEMBER destination, no allocation -> previously DROPPED, now abstained + missing=dest_capacity */
void eg_member(struct S *s, const char *src, int n) { memcpy(s->buf, src, n); }

/* ADDRESS-OF destination, no allocation -> abstained + missing=destination_capacity */
void eg_addrof(const char *src) { int obj; memcpy(&obj, src, 4); }

/* POINTER-ARITHMETIC destination -> abstained + missing=destination_capacity */
void eg_ptrarith(char *base, int off, const char *src, int n) { memcpy(base + off, src, n); }

/* BARE pointer, NO allocation -> abstained + required_evidence_absent (r01 regression) + missing */
void eg_bare_noalloc(char *p, const char *src, int n) { memcpy(p, src, n); }

/* BARE pointer WITH allocation -> open_candidate (UNCHANGED; capacity established) */
void eg_bare_alloc(const char *src, int n) { char *p = malloc(n); memcpy(p, src, n); free(p); }

/* BARE pointer WITH allocation, DIFFERENT width -> open_candidate (UNCHANGED) */
void eg_bare_alloc_open(const char *src, int n, int m) { char *p = malloc(n); memcpy(p, src, m); free(p); }
