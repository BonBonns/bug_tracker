/* NAPI-STATUS-R01 synthetic controls -- raw N-API return-code / output-initialization
 * handling shapes for napi_status_verdict.py. Each function is ONE control with ONE
 * expected classification (see check_napi_status.py for the authoritative expectations).
 *
 * This file is compiled with the pinned Joern (v4.0.608) c2cpg and exported with the same
 * export_c_cpp_facts_v03.sc as every other capability's frozen fixture facts. The N-API
 * declarations below mirror node_api.h's real signatures (argument order and out-parameter
 * roles) so the argument-role identities the analyzer keys on are the real ones; the
 * declarations are local so the fixture compiles hermetically, with no node headers needed.
 *
 * NOTE ON LANGUAGE: nothing here is a vulnerability claim. Every "expected finding" is a
 * STATUS_GUARD_MISSING *API-handling classification* -- "an output of a fallible call is
 * reachable without a proven-success guard" -- never an impact or exploitability statement.
 */

typedef unsigned long size_t;
typedef struct napi_env__*   napi_env;
typedef struct napi_value__* napi_value;
typedef enum { napi_ok = 0, napi_invalid_arg, napi_generic_failure } napi_status;

extern napi_status napi_create_buffer(napi_env env, size_t length,
                                      void** data, napi_value* result);
extern napi_status napi_create_buffer_copy(napi_env env, size_t length, const void* data,
                                           void** result_data, napi_value* result);
extern napi_status napi_create_external_buffer(napi_env env, size_t length, void* data,
                                               void* finalize_cb, void* finalize_hint,
                                               napi_value* result);

extern void fill_bytes(void* dst, size_t n);
extern void use_value(napi_value v);
extern void log_note(const char* msg);
extern napi_status external_status_filter(napi_status s);  /* body NOT available */
extern void abort(void);
extern int marker_true(void);
extern int marker_false(void);

/* ---- Control 1: unchecked status followed by output use -> STATUS_GUARD_MISSING ---- */
napi_value c01_unchecked_use(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  fill_bytes(data, 64);            /* output use with no status check anywhere before */
  return result;
}

/* ---- Control 2: correct terminating failure check -> STATUS_GUARD_ESTABLISHED ---- */
napi_value c02_checked_terminating(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  if (status != napi_ok) {
    return 0;                      /* failure path terminates before any output use */
  }
  fill_bytes(data, 64);
  return result;
}

/* ---- Control 3: status check occurring only AFTER output use -> STATUS_GUARD_MISSING - */
napi_value c03_check_after_use(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  fill_bytes(data, 64);            /* use happens first ... */
  if (status != napi_ok) {         /* ... the related check exists, but too late */
    return 0;
  }
  return result;
}

/* ---- Control 4: check of an UNRELATED status variable -> STATUS_GUARD_MISSING ---- */
napi_value c04_unrelated_status(napi_env env, napi_status other) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  if (other != napi_ok) {          /* different napi_status object entirely */
    return 0;
  }
  fill_bytes(data, 64);
  return result;
}

/* ---- Control 5: failure branch that does NOT terminate -> STATUS_GUARD_MISSING ---- */
napi_value c05_nonterminating_failure(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  if (status != napi_ok) {
    log_note("create failed");     /* logs, then falls through to the use */
  }
  fill_bytes(data, 64);
  return result;
}

/* ---- Control 6: direct status propagation before output use -> STATUS_PROPAGATED ---- */
napi_status c06_propagates(napi_env env, napi_value* out) {
  void* data;
  napi_status status = napi_create_buffer(env, 64, &data, out);
  return status;                   /* caller receives the status; no local output use */
}

/* ---- Control 6b: propagation by returning the call directly -> STATUS_PROPAGATED ---- */
napi_status c06b_propagates_direct(napi_env env, napi_value* out) {
  void* data;
  return napi_create_buffer(env, 64, &data, out);
}

/* ---- Control 7: output use EXCLUSIVELY in the proven success branch -> ESTABLISHED --- */
napi_value c07_use_in_success_branch(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 128, &data, &result);
  if (status == napi_ok) {
    fill_bytes(data, 128);
    use_value(result);
    return result;
  }
  return 0;
}

/* ---- Control 8: ambiguous output identity -> ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED ---- */
napi_value c08_ambiguous_output(napi_env env, napi_value* slots, int i) {
  void* data;
  napi_status status = napi_create_buffer(env, 64, &data, &slots[i]);
  if (status != napi_ok) {
    return 0;
  }
  return slots[i];
}

/* ---- Control 9: napi_create_external_buffer is UNSUPPORTED in this revision ----
 * Deliberately unchecked; the registration table must make this entire function
 * invisible (zero candidates, zero findings, zero abstentions), proving the
 * different-ownership API is excluded by registration, not by luck. ---- */
napi_value c09_external_buffer(napi_env env, void* ext) {
  napi_value result;
  napi_create_external_buffer(env, 64, ext, 0, 0, &result);
  return result;
}

/* ---- Control 10: KNOWN wrapper with proven propagation -> STATUS_GUARD_ESTABLISHED --
 * c10_filter's body is in this translation unit and provably returns its status
 * parameter unmodified on every path, so a check of c10_filter(status) is a check of
 * status. ---- */
static napi_status c10_filter(napi_status s) {
  return s;
}
napi_value c10_known_wrapper(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  if (c10_filter(status) != napi_ok) {
    return 0;
  }
  fill_bytes(data, 64);
  return result;
}

/* ---- Control 11: UNKNOWN wrapper -> ABSTAIN_WRAPPER_UNRESOLVED ----
 * external_status_filter has no body in the fact base; whether the check of its result
 * proves anything about status is unresolvable, and the analyzer must abstain rather
 * than either flag or clear the site. ---- */
napi_value c11_unknown_wrapper(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  if (external_status_filter(status) != napi_ok) {
    return 0;
  }
  fill_bytes(data, 64);
  return result;
}

/* ---- Probe: CFG branch-order/polarity verification (not a control of the property).
 * The analyzer relies on the pinned exporter emitting a condition node's TRUE successor
 * first in cfg_edges.tsv (the same convention resource_guard_verdict_r04.py's
 * resolve_branch_targets already depends on). These two probes let the gate verify that
 * convention against the real frozen facts and fail loudly if a regenerated fixture ever
 * breaks it. ---- */
int p01_polarity_ne(int x) {
  if (x != 0) {
    return marker_true();
  }
  return marker_false();
}
int p01_polarity_eq(int x) {
  if (x == 0) {
    return marker_true();
  }
  return marker_false();
}

/* ---- Probe: napi_create_buffer_copy coverage; status discarded entirely ->
 * STATUS_GUARD_MISSING, with input-size origin = parameter (diagnostic only). ---- */
napi_value p02_copy_unchecked(napi_env env, const void* src, size_t n) {
  void* data;
  napi_value result;
  napi_create_buffer_copy(env, n, src, &data, &result);
  return result;
}

/* ---- Probe: KNOWN wrapper proven to TERMINATE on failure -> ESTABLISHED.
 * p03_guard's body is local and provably reaches abort() on every s != napi_ok path,
 * so the call p03_guard(status) is a proven success barrier. ---- */
static void p03_guard(napi_status s) {
  if (s != napi_ok) {
    abort();
  }
}
napi_value p03_known_terminating_wrapper(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  p03_guard(status);
  fill_bytes(data, 64);
  return result;
}

/* ---- Probe: provable compound condition (success AND extra) -> ESTABLISHED.
 * On the true edge of `status == napi_ok && flag`, both operands are true, so success
 * is proven for every node inside the branch. ---- */
napi_value p04_compound_and(napi_env env, int flag) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  if (status == napi_ok && flag) {
    fill_bytes(data, 64);
    return result;
  }
  return 0;
}

/* ---- Probe: unprovable compound condition -> ABSTAIN_BRANCH_POLARITY_UNRESOLVED.
 * On the true edge of `status == napi_ok || flag`, success is NOT implied (flag alone
 * may have entered the branch); the analyzer must abstain, not flag and not clear. ---- */
napi_value p05_compound_or_ambiguous(napi_env env, int flag) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 64, &data, &result);
  if (status == napi_ok || flag) {
    fill_bytes(data, 64);
    return result;
  }
  return 0;
}

/* ---- Probe: outputs never used after the call -> NO_OUTPUT_USE (not a finding). ---- */
napi_value p06_no_use(napi_env env) {
  void* data;
  napi_value result;
  napi_status status = napi_create_buffer(env, 8, &data, &result);
  return 0;
}

/* ---- Probe: arity mismatch -> ABSTAIN_CALL_IDENTITY_UNRESOLVED.
 * A 3-argument call under napi_create_buffer's name does not match the registered
 * 4-argument role signature; identity is ambiguous, so the analyzer must abstain. ---- */
napi_value p07_wrong_arity(napi_env env) {
  void* data;
  napi_create_buffer(env, 64, &data);
  return 0;
}
