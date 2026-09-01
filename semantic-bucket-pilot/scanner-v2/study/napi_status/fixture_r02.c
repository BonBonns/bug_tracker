/* NAPI-STATUS-R02 synthetic controls -- the interprocedural boundary R01's blind run
 * exposed (@farcaster/rocksdb Convert): optional-vs-required output roles, NULL
 * opt-outs, required outputs escaping through callee parameters, one-level caller
 * analysis, and derived proven-propagating-wrapper sites. Compiled with the same
 * pinned Joern v4.0.608 + export_c_cpp_facts_v03.sc as every other frozen fixture.
 * Expectations live in check_napi_status_r02.py. Nothing here is a vulnerability
 * claim -- every expected finding is an API-handling classification.
 *
 * NOTE: `NULL` is deliberately left UNDECLARED, so c2cpg binds it to a synthetic
 * same-named local and emits an IDENTIFIER -- the exact representation in the frozen
 * rocksdb blind facts this revision regresses against. */

typedef unsigned long size_t;
typedef struct napi_env__*   napi_env;
typedef struct napi_value__* napi_value;
typedef enum { napi_ok = 0, napi_invalid_arg, napi_generic_failure } napi_status;

extern napi_status napi_create_buffer(napi_env env, size_t length,
                                      void** data, napi_value* result);
extern napi_status napi_create_buffer_copy(napi_env env, size_t length, const void* data,
                                           void** result_data, napi_value* result);

extern void fill_bytes(void* dst, size_t n);
extern void use_value(napi_value v);

/* ---- w_make: proven-propagating creation wrapper (registered by R02's strict
 * propagation proof: single return, returns the creation call directly; both outputs
 * forwarded through parameters). Its own site: STATUS_PROPAGATED_BEFORE_USE. ---- */
static napi_status w_make(napi_env env, size_t n, void** data, napi_value* out) {
  return napi_create_buffer(env, n, data, out);
}

/* ---- w01: caller of the proven wrapper CHECKS the propagated status, then uses ->
 * derived site STATUS_GUARD_ESTABLISHED (real positive-path caller machinery). ---- */
napi_value w01_caller_checked(napi_env env) {
  void* d;
  napi_value v;
  napi_status st = w_make(env, 32, &d, &v);
  if (st != napi_ok) {
    return 0;
  }
  use_value(v);
  return v;
}

/* ---- w02: caller of the proven wrapper DISCARDS the status, then uses ->
 * derived site STATUS_GUARD_MISSING / STATUS_DISCARDED. ---- */
napi_value w02_caller_unchecked(napi_env env) {
  void* d;
  napi_value v;
  w_make(env, 32, &d, &v);
  use_value(v);
  return v;
}

/* ---- w03: callee DISCARDS the status and the required output escapes; the one
 * TU-visible caller resolves (&local) and uses the output -> the w_fill napi site is
 * STATUS_GUARD_MISSING / STATUS_DISCARDED_OUTPUT_USED_IN_CALLER (caller evidence). */
static void w_fill(napi_env env, napi_value* out) {
  void* d;
  napi_create_buffer(env, 16, &d, out);
}
napi_value w03_caller_uses(napi_env env) {
  napi_value v;
  w_fill(env, &v);
  use_value(v);
  return v;
}

/* ---- w04: the rocksdb Convert shape -- callee discards the status, required output
 * escapes, and the caller passes ITS OWN parameter (second-level escape) -> the
 * w_convert napi site is OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED. ---- */
static void w_convert(napi_env env, napi_value* out) {
  void* d;
  napi_create_buffer(env, 16, &d, out);
}
void w04_caller_level2(napi_env env, napi_value* result) {
  w_convert(env, result);
}

/* ---- w05: NULL opt-out of the OPTIONAL result_data role; the required result is a
 * local, used unchecked -> STATUS_GUARD_MISSING / STATUS_DISCARDED, with the
 * opted-out role recorded and NEVER tracked as a use target. ---- */
napi_value w05_null_optout(napi_env env, const void* src, size_t n) {
  napi_value v;
  napi_create_buffer_copy(env, n, src, NULL, &v);
  return v;
}

/* ---- w06: NULL in the REQUIRED result role -> ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED /
 * REQUIRED_OUTPUT_NULL. ---- */
napi_value w06_null_required(napi_env env) {
  void* d;
  napi_create_buffer(env, 8, &d, NULL);
  return 0;
}

/* ---- w07: callee discards the status, required output escapes, and NO caller is
 * visible in this fact base -> OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED /
 * NO_CALLER_FACTS. ---- */
static void w07_orphan(napi_env env, napi_value* out) {
  void* d;
  napi_create_buffer(env, 8, &d, out);
}

/* ---- w08: callee discards the status and the required output escapes, but every
 * TU-visible caller resolves and never uses the output ->
 * NO_OUTPUT_USE_IN_KNOWN_CALLERS (a TU-scoped statement, not NO_OUTPUT_USE). ---- */
static void w_ignore(napi_env env, napi_value* out) {
  void* d;
  napi_create_buffer(env, 8, &d, out);
}
void w08_caller_never_uses(napi_env env) {
  napi_value v;
  w_ignore(env, &v);
}
