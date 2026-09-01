/* BOUNDED FAILURE-INJECTION harness for the NAPI-STATUS finding in
 * @8crafter/leveldb-zlib NextWorker::HandleOKCallback (bindings.cpp:1440->1453).
 *
 * Purpose: observe the RUNTIME control-flow behavior of the return-code handling when
 * napi_create_buffer_copy FAILS -- i.e., does the program use the required output
 * (returnKey) afterward without a success check? This is a reliability observation of
 * return-code handling. It is NOT an exploit, NOT an impact/severity claim, and uses
 * only local stubs (no real N-API, node, or leveldb). Deterministic and self-contained.
 *
 * The control flow below is the EXACT shape of the real site: the required output is
 * declared, napi_create_buffer_copy is called with its status DISCARDED, and the output
 * is then passed to napi_set_element regardless of success -- exactly what the static
 * finding states. The stub simulates a real failure: it returns a non-ok status and does
 * NOT write *result (the documented N-API contract on failure -- the output is left
 * unavailable). A poison sentinel makes "unavailable/indeterminate" observable. */
#include <cstdio>
#include <cstdint>

typedef struct napi_env__*   napi_env;
typedef struct napi_value__* napi_value;
typedef enum { napi_ok = 0, napi_generic_failure = 1 } napi_status;

static bool g_fail = false;
static const napi_value POISON = (napi_value)(uintptr_t)0xDEADBEEFDEADBEEFULL;

/* napi_create_buffer_copy stub. On success: writes a real handle to *result and returns
 * napi_ok. On injected failure: returns napi_generic_failure and DOES NOT touch *result
 * (the real N-API failure contract -- the output stays whatever it was). */
static napi_status napi_create_buffer_copy(napi_env, unsigned long, const void*,
                                           void**, napi_value* result) {
  if (g_fail) return napi_generic_failure;          /* output left unavailable */
  *result = (napi_value)(uintptr_t)0x1000;          /* a real created handle */
  return napi_ok;
}

/* Instrumented sink: records the value the code passes downstream on the use path. */
static napi_value g_used_value = nullptr;
static napi_status napi_set_element(napi_env, napi_value, unsigned, napi_value v) {
  g_used_value = v;
  return napi_ok;
}

/* EXACT control-flow shape of NextWorker::HandleOKCallback's buffer branch + use.
 * returnKey is seeded to POISON to MODEL indeterminate prior stack content (the real
 * code leaves it uninitialized; seeding a known sentinel makes the "unavailable on
 * failure" behavior deterministic and observable). The create/use structure below is
 * otherwise identical to the real site. */
static void handle_ok_callback_shape(napi_env env, napi_value jsArray) {
  napi_value returnKey = POISON;   /* models indeterminate prior content (real: uninit) */
  /* status DISCARDED -- no assignment, no check (the finding) */
  napi_create_buffer_copy(env, 3, "key", nullptr, &returnKey);
  napi_set_element(env, jsArray, 1, returnKey);      /* output USED regardless of status */
}

int main() {
  napi_env env = nullptr;
  napi_value arr = (napi_value)(uintptr_t)0x2000;

  /* success path */
  g_fail = false; g_used_value = nullptr;
  handle_ok_callback_shape(env, arr);
  printf("SUCCESS path: napi_set_element received %p (a real created handle)\n",
         (void*)g_used_value);
  bool ok_real = (g_used_value == (napi_value)(uintptr_t)0x1000);

  /* injected-failure path */
  g_fail = true; g_used_value = nullptr;
  handle_ok_callback_shape(env, arr);
  printf("FAILURE path: napi_set_element received %p (the unavailable/uninitialized output)\n",
         (void*)g_used_value);
  bool used_unavailable = (g_used_value != (napi_value)(uintptr_t)0x1000);

  printf("\nOBSERVED RUNTIME BEHAVIOR:\n");
  printf("  - success: the created handle flows to the use site: %s\n",
         ok_real ? "yes" : "no");
  printf("  - injected failure: the output is USED on the failure path without a success "
         "check, carrying an unavailable/indeterminate value (not a created handle): %s\n",
         used_unavailable ? "yes" : "no");
  printf("\nThis is a runtime observation of return-code handling only. No security "
         "impact, severity, or exploitability is claimed or established.\n");
  return (ok_real && used_unavailable) ? 0 : 2;
}
