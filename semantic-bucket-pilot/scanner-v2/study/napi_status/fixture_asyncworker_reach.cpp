/* NAPI-STATUS reachability regression: the async-worker structural break that keeps
 * @8crafter/leveldb-zlib's NextWorker::HandleOKCallback (the two STATUS_GUARD_MISSING
 * sites) at TIER_INTERNAL_UNREGISTERED. Distilled VERBATIM in structure from
 * src/bindings.cpp (BaseWorker + NextWorker + iterator_next + Init), types stubbed to
 * compile hermetically with the pinned Joern v4.0.608 c2cpg. Reproduces exactly the
 * fact pattern the real trace found (HANDLEOK_REACHABILITY_TRACE.json):
 *
 *   - napi_create_async_work registers the STATIC trampolines Execute/Complete
 *     (METHOD_REFs) -- NOT HandleOKCallback.
 *   - Complete -> DoComplete -> HandleOKCallback is a VIRTUAL call the frontend binds
 *     to the BASE (BaseWorker::HandleOKCallback), so the DERIVED override
 *     (NextWorker::HandleOKCallback) has NO incoming call edge.
 *   - iterator_next (a registered JS export) constructs + queues NextWorker, but the
 *     final hop to the derived override is invisible (second-order handoff + virtual
 *     dispatch).
 *
 * So the derived override is not registered, not transitively reached by a clean
 * single-target edge, not module-load reached, and not a callback/worker method-ref
 * target -> TIER_INTERNAL_UNREGISTERED. Correct and conservative: the facts cannot
 * prove a unique JS-to-native chain to the site. No security or runtime claim. */

typedef unsigned long size_t;
typedef struct napi_env__*   napi_env;
typedef struct napi_value__* napi_value;
typedef struct napi_async_work__* napi_async_work;
typedef enum { napi_ok = 0 } napi_status;
typedef napi_value (*napi_callback)(napi_env, void*);

extern napi_status napi_create_buffer_copy(napi_env, size_t, const void*, void**, napi_value*);
extern napi_status napi_create_async_work(napi_env, napi_value, napi_value,
                                          void (*)(napi_env, void*),
                                          void (*)(napi_env, napi_status, void*),
                                          void*, napi_async_work*);
extern napi_status napi_queue_async_work(napi_env, napi_async_work);
extern napi_status napi_set_named_property(napi_env, napi_value, const char*, napi_value);
extern napi_status napi_create_function(napi_env, const char*, size_t, napi_callback,
                                        void*, napi_value*);
extern napi_status napi_get_null(napi_env, napi_value*);
extern napi_status napi_set_element(napi_env, napi_value, unsigned, napi_value);
extern napi_status napi_create_array_with_length(napi_env, size_t, napi_value*);

struct Str { const char* data(); size_t size(); };

struct BaseWorker {
  napi_env env_;
  napi_async_work asyncWork_;
  BaseWorker(napi_env env, napi_value cb) : env_(env) {
    napi_create_async_work(env_, cb, cb, BaseWorker::Execute, BaseWorker::Complete,
                           this, &asyncWork_);
  }
  virtual ~BaseWorker() {}
  static void Execute(napi_env env, void* data) { ((BaseWorker*)data)->DoExecute(); }
  static void Complete(napi_env env, napi_status status, void* data) {
    BaseWorker* self = (BaseWorker*)data;
    self->DoComplete();
    delete self;
  }
  void DoComplete() { return HandleOKCallback(); }   // virtual call, binds to base
  virtual void DoExecute() = 0;
  virtual void HandleOKCallback() {                  // BASE override
    napi_value argv;
    napi_get_null(env_, &argv);
  }
  void Queue() { napi_queue_async_work(env_, asyncWork_); }
};

struct NextWorker final : public BaseWorker {
  Str key_;
  Str value_;
  NextWorker(napi_env env, napi_value cb) : BaseWorker(env, cb) {}
  void DoExecute() override {}
  void HandleOKCallback() override {                 // DERIVED override -- the finding site
    napi_value jsArray;
    napi_create_array_with_length(env_, 2, &jsArray);
    napi_value returnKey;
    napi_create_buffer_copy(env_, key_.size(), key_.data(), 0, &returnKey);   // STATUS_DISCARDED
    napi_value returnValue;
    napi_create_buffer_copy(env_, value_.size(), value_.data(), 0, &returnValue); // STATUS_DISCARDED
    napi_set_element(env_, jsArray, 1, returnKey);    // required output used, no guard
    napi_set_element(env_, jsArray, 0, returnValue);  // required output used, no guard
  }
};

// Registered JS export: constructs + queues NextWorker.
napi_value iterator_next(napi_env env, void* info) {
  napi_value cb;
  NextWorker* worker = new NextWorker(env, cb);
  worker->Queue();
  return 0;
}

// Module init: registers iterator_next as a JS-facing property.
napi_value Init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "iteratorNext", 12, (napi_callback)iterator_next, 0, &fn);
  napi_set_named_property(env, exports, "iteratorNext", fn);
  return exports;
}
