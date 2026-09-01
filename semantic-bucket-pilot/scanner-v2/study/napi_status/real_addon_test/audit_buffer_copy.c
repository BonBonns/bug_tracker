#define _GNU_SOURCE
#include <link.h>
#include <bits/link_lavcurrent.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

typedef struct napi_env__* napi_env;
typedef struct napi_value__* napi_value;
typedef int napi_status;
#define NAPI_GENERIC_FAILURE 1

static napi_status forced_fail_buffer_copy(napi_env env, size_t length, const void* data,
                                           void** result_data, napi_value* result) {
  fprintf(stderr, "[audit-interpose] napi_create_buffer_copy(length=%zu) FORCED FAILURE "
                  "(output left untouched)\n", length);
  fflush(stderr);
  return NAPI_GENERIC_FAILURE;
}

unsigned int la_version(unsigned int v) {
  fprintf(stderr, "[audit] la_version v=%u\n", v);
  return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
  fprintf(stderr, "[audit] la_objopen: %s\n", map->l_name && map->l_name[0] ? map->l_name : "(main)");
  return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

uintptr_t la_symbind64(Elf64_Sym* sym, unsigned int ndx, uintptr_t* refcook,
                       uintptr_t* defcook, unsigned int* flags, const char* symname) {
  if (symname && strstr(symname, "buffer_copy")) {
    fprintf(stderr, "[audit] symbind: %s -> %#lx\n", symname, (unsigned long)sym->st_value);
  }
  if (symname && strcmp(symname, "napi_create_buffer_copy") == 0) {
    fprintf(stderr, "[audit-interpose] redirecting napi_create_buffer_copy bind "
                    "(orig addr %#lx) -> forced_fail_buffer_copy\n", (unsigned long)sym->st_value);
    return (uintptr_t)forced_fail_buffer_copy;
  }
  return sym->st_value;
}
