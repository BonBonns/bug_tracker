/* LD_PRELOAD test-only interposition shim, v2 (per review spec).
 *
 * napi_create_buffer_copy:
 *   - UNARMED (baseline): delegates to the REAL implementation via
 *     dlsym(RTLD_NEXT, ...) -- normal behavior, real created values.
 *   - ARMED (env NAPI_SHIM_ARM_BUFFER_COPY=1): returns failure (napi_generic_failure)
 *     WITHOUT writing *result -- the real N-API failure contract -- and increments/logs
 *     an injected-call counter.
 *
 * napi_set_element: ALWAYS intercepted (both armed and unarmed), records that
 * execution reached it (increments/logs a reach counter with the call's env/object/
 * index -- never dereferencing `value`, per the review's explicit instruction that
 * examining an indeterminate pointer is unnecessary and unreliable), and returns
 * safely (napi_ok) without touching *value or calling into the real implementation.
 * This makes "did the real code reach napi_set_element after the injected failure"
 * directly, safely observable without needing (or risking) a crash.
 *
 * Independent-verification markers: every intercepted call prints a fixed, greppable
 * line to stderr; a companion LD_DEBUG=bindings run additionally confirms (or refutes)
 * that the dynamic linker actually bound the addon's own PLT/GOT entries to THIS
 * library rather than to the host process.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

typedef struct napi_env__* napi_env;
typedef struct napi_value__* napi_value;
typedef int napi_status;
#define NAPI_GENERIC_FAILURE 1

typedef napi_status (*create_buffer_copy_fn)(napi_env, size_t, const void*, void**,
                                             napi_value*);
typedef napi_status (*set_element_fn)(napi_env, napi_value, unsigned int, napi_value);

static int g_buffer_copy_calls = 0;
static int g_set_element_reached = 0;

napi_status napi_create_buffer_copy(napi_env env, size_t length, const void* data,
                                    void** result_data, napi_value* result) {
  g_buffer_copy_calls++;
  const char* armed = getenv("NAPI_SHIM_ARM_BUFFER_COPY");
  if (armed && armed[0] == '1') {
    fprintf(stderr, "[shim] napi_create_buffer_copy call #%d (length=%zu): ARMED, "
                    "FORCING FAILURE, *result NOT written\n", g_buffer_copy_calls,
            length);
    fflush(stderr);
    return NAPI_GENERIC_FAILURE;
  }
  fprintf(stderr, "[shim] napi_create_buffer_copy call #%d (length=%zu): unarmed, "
                  "delegating to the real implementation\n", g_buffer_copy_calls,
          length);
  fflush(stderr);
  static create_buffer_copy_fn real_fn = NULL;
  if (!real_fn) {
    real_fn = (create_buffer_copy_fn)dlsym(RTLD_NEXT, "napi_create_buffer_copy");
  }
  if (!real_fn) {
    fprintf(stderr, "[shim] ERROR: dlsym(RTLD_NEXT, napi_create_buffer_copy) "
                    "returned NULL -- cannot delegate\n");
    return NAPI_GENERIC_FAILURE;
  }
  return real_fn(env, length, data, result_data, result);
}

napi_status napi_set_element(napi_env env, napi_value object, unsigned int index,
                             napi_value value) {
  g_set_element_reached++;
  /* Deliberately never dereferences `value` -- only its raw pointer identity is
   * logged, per the review's instruction that a particular pointer value is not the
   * meaningful observation; reachability is. */
  fprintf(stderr, "[shim] napi_set_element REACHED (call #%d): env=%p object=%p "
                  "index=%u value_ptr=%p -- recording reach, returning safely "
                  "WITHOUT dereferencing value\n", g_set_element_reached,
          (void*)env, (void*)object, index, (void*)value);
  fflush(stderr);
  return 0;  /* napi_ok -- safe no-op, real object/array is left unmodified */
}
