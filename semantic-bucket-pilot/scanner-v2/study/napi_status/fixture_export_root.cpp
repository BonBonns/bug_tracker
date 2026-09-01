/* NAPI-EXPORT-ROOT-R01 controls. Each module-init-like function or helper exercises one
 * establish/abstain shape for the create_function -> same-value set_named_property(exports)
 * -> module-init-returns-exports chain. Name-agnostic recognizer: class/function names
 * here are only for the gate to address each case. Compiled with pinned Joern v4.0.608.
 * No security or runtime claim -- native export-root reachability structure only. */

typedef struct napi_env__*   napi_env;
typedef struct napi_value__* napi_value;
typedef struct napi_callback_info__* napi_callback_info;
typedef enum { napi_ok = 0 } napi_status;
typedef napi_value (*napi_callback)(napi_env, napi_callback_info);

extern napi_status napi_create_function(napi_env, const char*, unsigned long,
                                        napi_callback, void*, napi_value*);
extern napi_status napi_set_named_property(napi_env, napi_value, const char*, napi_value);
extern napi_status napi_define_properties(napi_env, napi_value, unsigned long, const void*);

/* real callbacks (each a distinct NAPI method) */
napi_value cb1(napi_env e, napi_callback_info i) { return 0; }
napi_value cb2(napi_env e, napi_callback_info i) { return 0; }
napi_value cb3(napi_env e, napi_callback_info i) { return 0; }
napi_value cb4(napi_env e, napi_callback_info i) { return 0; }
napi_value cb6(napi_env e, napi_callback_info i) { return 0; }
napi_value cb7(napi_env e, napi_callback_info i) { return 0; }
napi_value cb8(napi_env e, napi_callback_info i) { return 0; }
napi_value cb9a(napi_env e, napi_callback_info i) { return 0; }
napi_value cb9b(napi_env e, napi_callback_info i) { return 0; }
napi_value cb_never_exported(napi_env e, napi_callback_info i) { return 0; }  /* control 12 */

/* ambiguous callback identity (control 5): two same-named overloads */
napi_value amb(napi_env e, napi_callback_info i) { return 0; }
napi_value amb(napi_env e, int x) { return 0; }

/* --- Control 1: exact chain -> establish cb1 --- */
napi_value init_c1(napi_env env, napi_value exports) {
  napi_value fn1;
  napi_create_function(env, "cb1", 3, cb1, 0, &fn1);
  napi_set_named_property(env, exports, "cb1", fn1);
  return exports;
}

/* --- Control 2: created function never attached -> abstain --- */
napi_value init_c2(napi_env env, napi_value exports) {
  napi_value fn2;
  napi_create_function(env, "cb2", 3, cb2, 0, &fn2);   /* fn2 never set as a property */
  return exports;
}

/* --- Control 3: a DIFFERENT napi_value attached -> abstain --- */
napi_value init_c3(napi_env env, napi_value exports, napi_value other) {
  napi_value fn3;
  napi_create_function(env, "cb3", 3, cb3, 0, &fn3);
  napi_set_named_property(env, exports, "cb3", other);  /* attaches other, not fn3 */
  return exports;
}

/* --- Control 4: property attached to a DIFFERENT object -> abstain --- */
napi_value init_c4(napi_env env, napi_value exports, napi_value notexports) {
  napi_value fn4;
  napi_create_function(env, "cb4", 3, cb4, 0, &fn4);
  napi_set_named_property(env, notexports, "cb4", fn4); /* not the returned exports */
  return exports;
}

/* --- Control 5: ambiguous callback identity -> abstain --- */
napi_value init_c5(napi_env env, napi_value exports) {
  napi_value fn5;
  napi_create_function(env, "amb", 3, amb, 0, &fn5);    /* amb is overloaded -> ambiguous */
  napi_set_named_property(env, exports, "amb", fn5);
  return exports;
}

/* --- Control 6: callback argument is not a method reference -> abstain --- */
napi_value init_c6(napi_env env, napi_value exports) {
  napi_callback cbvar = cb6;                            /* a variable, not a direct ref */
  napi_value fn6;
  napi_create_function(env, "cb6", 3, cbvar, 0, &fn6);
  napi_set_named_property(env, exports, "cb6", fn6);
  return exports;
}

/* --- Control 7: registration outside a proven module initializer -> abstain ---
 * reg7 is a free helper whose obj is NOT returned as module exports by any init. */
void reg7(napi_env env, napi_value obj) {
  napi_value fn7;
  napi_create_function(env, "cb7", 3, cb7, 0, &fn7);
  napi_set_named_property(env, obj, "cb7", fn7);
}

/* --- Control 8: initializer returns a DIFFERENT exports object -> abstain --- */
napi_value init_c8(napi_env env, napi_value exports, napi_value other2) {
  napi_value fn8;
  napi_create_function(env, "cb8", 3, cb8, 0, &fn8);
  napi_set_named_property(env, exports, "cb8", fn8);
  return other2;                                        /* returns a different object */
}

/* --- Control 9: multiple created-function defs reach the property call -> abstain --- */
napi_value init_c9(napi_env env, napi_value exports) {
  napi_value fn9;
  napi_create_function(env, "cb9a", 4, cb9a, 0, &fn9);
  napi_create_function(env, "cb9b", 4, cb9b, 0, &fn9);  /* same value var fn9 */
  napi_set_named_property(env, exports, "cb9", fn9);
  return exports;
}

/* --- Control 10: unsupported napi_define_properties idiom -> explicit abstention --- */
napi_value init_c10(napi_env env, napi_value exports) {
  napi_define_properties(env, exports, 0, 0);
  return exports;
}
