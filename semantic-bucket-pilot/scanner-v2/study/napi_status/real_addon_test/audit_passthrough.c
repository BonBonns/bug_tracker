#define _GNU_SOURCE
#include <link.h>
#include <bits/link_lavcurrent.h>
#include <stdio.h>

/* Control: identical LD_AUDIT machinery, but NEVER redirects any symbol -- isolates
 * whether a crash is caused by the forced-failure interposition itself, versus being
 * an artifact of running under LD_AUDIT at all. */
unsigned int la_version(unsigned int v) { return LAV_CURRENT; }
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
  return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}
uintptr_t la_symbind64(Elf64_Sym* sym, unsigned int ndx, uintptr_t* refcook,
                       uintptr_t* defcook, unsigned int* flags, const char* symname) {
  return sym->st_value;  /* pass through unchanged, always */
}
