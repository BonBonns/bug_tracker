#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static char gbuf[256];
void safe_local(const char* s){ char dst[64]; snprintf(dst, sizeof(dst), "%s", s); }          /* SUPPRESS */
void safe_global(const char* s){ snprintf(gbuf, sizeof(gbuf), "%s", s); }                       /* SUPPRESS */
void wrong_buffer(const char* s){ char dst[32]; char other[128]; snprintf(dst, sizeof(other), "%s", s); (void)other; } /* CANDIDATE */
void pointer_sizeof(const char* s){ char* p = malloc(4); snprintf(p, sizeof(p), "%s", s); free(p);} /* CANDIDATE */
void sizeof_plus_one(const char* s){ char dst[32]; snprintf(dst, sizeof(dst)+1, "%s", s);}      /* CANDIDATE */
void variable_extent(const char* s, int n){ char dst[32]; snprintf(dst, n, "%s", s);}           /* unaffected */
int main(void){ return 0; }
