/* Test-only LINK-TIME interposition, via -Wl,--wrap. Unlike LD_PRELOAD (verified
 * PREBUILT_INTERPOSITION_UNAVAILABLE against the shipped prebuilt -- see
 * ld_preload_v2_binding_evidence.txt), --wrap resolves at LINK time within this one
 * translation unit set: the linker renames every call FROM THIS PACKAGE'S OWN OBJECT
 * FILES to napi_create_buffer_copy/napi_set_element into a call to
 * __wrap_napi_create_buffer_copy/__wrap_napi_set_element (defined here), and renames
 * the ORIGINAL (still-undefined, resolved at runtime against the host node process,
 * exactly as before) symbol to __real_napi_create_buffer_copy/__real_napi_set_element.
 * This is immune to the runtime global-scope symbol-binding behavior that defeated
 * LD_PRELOAD for this addon+node combination -- it never depends on the dynamic
 * linker choosing our definition over node's at load time. */
#include <node_api.h>
#include <cstdio>
#include <cstdlib>
#include <cstddef>

extern "C" {

napi_status __real_napi_create_buffer_copy(napi_env env, size_t length,
                                           const void* data, void** result_data,
                                           napi_value* result);
napi_status __real_napi_set_element(napi_env env, napi_value object, uint32_t index,
                                    napi_value value);

static int g_buffer_copy_calls = 0;
static int g_set_element_reached = 0;

napi_status __wrap_napi_create_buffer_copy(napi_env env, size_t length,
                                           const void* data, void** result_data,
                                           napi_value* result) {
  g_buffer_copy_calls++;
  const char* armed = getenv("NAPI_SHIM_ARM_BUFFER_COPY");
  if (armed && armed[0] == '1') {
    fprintf(stderr, "[wrap] napi_create_buffer_copy call #%d (length=%zu): ARMED, "
                    "FORCING FAILURE, *result NOT written\n", g_buffer_copy_calls,
            length);
    fflush(stderr);
    return napi_generic_failure;
  }
  fprintf(stderr, "[wrap] napi_create_buffer_copy call #%d (length=%zu): unarmed, "
                  "delegating to __real_napi_create_buffer_copy\n",
          g_buffer_copy_calls, length);
  fflush(stderr);
  return __real_napi_create_buffer_copy(env, length, data, result_data, result);
}

napi_status __wrap_napi_set_element(napi_env env, napi_value object, uint32_t index,
                                    napi_value value) {
  g_set_element_reached++;
  /* Never dereferences `value` -- only its raw pointer identity is logged (the
   * meaningful observation is reachability, not the pointer's content). */
  fprintf(stderr, "[wrap] napi_set_element REACHED (call #%d): env=%p object=%p "
                  "index=%u value_ptr=%p -- recording reach, returning safely "
                  "WITHOUT dereferencing value or calling the real implementation\n",
          g_set_element_reached, (void*)env, (void*)object, index, (void*)value);
  fflush(stderr);
  return napi_ok;  /* safe no-op */
}

}  // extern "C"
