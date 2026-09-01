/* VIRTUAL-DISPATCH-REACHABILITY-R01 controls. Multiple independent async-worker
 * families, each exercising ONE promote/abstain shape. The analysis is name-agnostic;
 * class/method names here are only for the gate to address each case. Compiled with the
 * pinned Joern v4.0.608 c2cpg; frozen facts drive check_virtual_dispatch_reachability.py.
 * No security or runtime claim -- this is reachability structure only. */

typedef unsigned long size_t;
typedef struct napi_env__*   napi_env;
typedef struct napi_value__* napi_value;
typedef struct napi_async_work__* napi_async_work;
typedef enum { napi_ok = 0 } napi_status;

extern napi_status napi_create_async_work(napi_env, napi_value, napi_value,
                                          void (*)(napi_env, void*),
                                          void (*)(napi_env, napi_status, void*),
                                          void*, napi_async_work*);
extern napi_status napi_queue_async_work(napi_env, napi_async_work);
extern void sink(napi_value);

/* ---------- Control 1: one concrete derived worker -> override reached ---------- */
struct W1Base {
  napi_env env_; napi_async_work work_;
  W1Base(napi_env e) : env_(e) {
    napi_create_async_work(e, 0, 0, W1Base::Execute, W1Base::Complete, this, &work_);
  }
  virtual ~W1Base() {}
  static void Execute(napi_env e, void* d) { ((W1Base*)d)->DoExecute(); }
  static void Complete(napi_env e, napi_status s, void* d) {
    W1Base* self = (W1Base*)d; self->DoComplete(); delete self;
  }
  void DoComplete() { HandleOKCallback(); }
  virtual void DoExecute() = 0;
  virtual void HandleOKCallback() {}
  void Queue() { napi_queue_async_work(env_, work_); }
};
struct W1Next final : public W1Base {
  W1Next(napi_env e) : W1Base(e) {}
  void DoExecute() override {}
  void HandleOKCallback() override { napi_value v; sink(v); }   // <- must be PROMOTED
};
napi_value c1_export(napi_env env, void* info) {
  W1Next* w = new W1Next(env); w->Queue(); return 0;
}

/* ---------- Control 2: two possible derived workers (ambiguous receiver) -> abstain --- */
struct W2Next final : public W1Base {
  W2Next(napi_env e) : W1Base(e) {}
  void DoExecute() override {}
  void HandleOKCallback() override { napi_value v; sink(v); }
};
napi_value c2_export(napi_env env, void* info, int cond) {
  W1Base* w;
  if (cond) { w = new W1Next(env); } else { w = new W2Next(env); }  // receiver ambiguous
  w->Queue();
  return 0;
}

/* ---------- Control 3: base-class allocation -> derived override NOT reached ---------- */
struct W3Base {
  napi_env env_; napi_async_work work_;
  W3Base(napi_env e) : env_(e) {
    napi_create_async_work(e, 0, 0, W3Base::Execute, W3Base::Complete, this, &work_);
  }
  virtual ~W3Base() {}
  static void Execute(napi_env e, void* d) {}
  static void Complete(napi_env e, napi_status s, void* d) {
    W3Base* self = (W3Base*)d; self->DoComplete(); delete self;
  }
  void DoComplete() { HandleOKCallback(); }
  virtual void HandleOKCallback() { napi_value v; sink(v); }    // base override (reached)
  void Queue() { napi_queue_async_work(env_, work_); }
};
struct W3Derived final : public W3Base {
  W3Derived(napi_env e) : W3Base(e) {}
  void HandleOKCallback() override { napi_value v; sink(v); }   // NOT reached (base alloc'd)
};
napi_value c3_export(napi_env env, void* info) {
  W3Base* w = new W3Base(env); w->Queue(); return 0;            // base allocated, not derived
}

/* ---------- Control 4: callback registered with a DIFFERENT data pointer -> abstain --- */
struct W4Base {
  napi_env env_; napi_async_work work_; void* other_;
  W4Base(napi_env e, void* other) : env_(e), other_(other) {
    napi_create_async_work(e, 0, 0, W4Base::Execute, W4Base::Complete, other, &work_);  // data=other, not this
  }
  virtual ~W4Base() {}
  static void Execute(napi_env e, void* d) {}
  static void Complete(napi_env e, napi_status s, void* d) {
    W4Base* self = (W4Base*)d; self->DoComplete(); delete self;
  }
  void DoComplete() { HandleOKCallback(); }
  virtual void HandleOKCallback() {}
  void Queue() { napi_queue_async_work(env_, work_); }
};
struct W4Next final : public W4Base {
  W4Next(napi_env e, void* o) : W4Base(e, o) {}
  void HandleOKCallback() override { napi_value v; sink(v); }   // NOT promoted (data != this)
};
napi_value c4_export(napi_env env, void* info, void* other) {
  W4Next* w = new W4Next(env, other); w->Queue(); return 0;
}

/* ---------- Control 5: receiver reassigned before callback -> abstain ---------- */
napi_value c5_export(napi_env env, void* info, W1Base* existing) {
  W1Base* w = new W1Next(env);
  w = existing;                 // reassigned: the queued object is not the allocated one
  w->Queue();
  return 0;
}

/* ---------- Control 6: factory return with unresolved concrete type -> abstain ---------- */
extern W1Base* makeWorker(napi_env);
napi_value c6_export(napi_env env, void* info) {
  W1Base* w = makeWorker(env);  // concrete type unresolved
  w->Queue();
  return 0;
}

/* ---------- Control 7: virtual method signature mismatch -> abstain ---------- */
struct W7Next final : public W1Base {
  W7Next(napi_env e) : W1Base(e) {}
  void DoExecute() override {}
  void HandleOKCallback(int x) { napi_value v; sink(v); }       // different signature: NOT an override
};
napi_value c7_export(napi_env env, void* info) {
  W7Next* w = new W7Next(env); w->Queue(); return 0;
}

/* ---------- Control 8: callback NOT registered -> no promotion ---------- */
struct W8Base {
  napi_env env_;
  W8Base(napi_env e) : env_(e) {}   // no napi_create_async_work anywhere
  virtual ~W8Base() {}
  virtual void HandleOKCallback() { napi_value v; sink(v); }
  void Queue() {}
};
struct W8Next final : public W8Base {
  W8Next(napi_env e) : W8Base(e) {}
  void HandleOKCallback() override { napi_value v; sink(v); }   // NOT promoted (no registration)
};
napi_value c8_export(napi_env env, void* info) {
  W8Next* w = new W8Next(env); w->Queue(); return 0;
}
