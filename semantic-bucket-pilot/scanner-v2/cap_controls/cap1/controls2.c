#include <string.h>
struct S { char *ptr; int indx; int len; };
/* SNDSHAPE: struct-field base (realloc'd) -> recognize but capacity UNRESOLVED (no assume) */
void sndshape(struct S *s, char *src, int size){ memcpy(&(s->ptr[s->indx]), src, size); }
/* UNIT: int array, offset in elements, width k*sizeof(int) -> remaining in elements */
void unitcase(int *src){ int ibuf[10]; memcpy(&ibuf[2], src, 5*sizeof(int)); }
/* NONARRAY: base is a scalar pointer param (not an array decl) -> unresolved, no false bind */
void nonarray(char *p, char *src, int n){ memcpy(&p[3], src, n); }
/* AMBIG: two array decls named buf in different scopes of one function */
void ambig(char *src, int n, int c){ if(c){ char buf[10]; memcpy(&buf[1], src, n);} else { char buf[99]; memcpy(&buf[1], src, n);} }
