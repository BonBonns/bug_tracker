// RESOURCE-GUARD-R05 negative-control fixture. Real #include <napi.h> (the real, staged
// node-addon-api header -- same mechanism run_pipeline_one.py's header-staging fix uses),
// because AB_FIXTURE_RESULT.md confirmed a minimal synthetic stub does NOT reproduce the
// real <unresolvedNamespace> shape R05 recovers from -- only the real header does. Every
// function below is real, standalone-compiling C++ (see BUILD.md for the exact command).

#include <napi.h>

void UseBufferData(unsigned char *data, unsigned long length);
unsigned char *GetExternalPointer();

// --- Positive-shape sanity check (Buffer::New, 2-arg allocating overload, unguarded,
// downstream use) -- NOT R05's primary positive proof (that is the real Cartesi recovery,
// see R05_DESIGN.md/task #5); included here only so this fixture's own facts contain one
// real recoverable call alongside the negative controls, for a same-file sanity cross-check.
Napi::Value PositiveBufferNew(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    unsigned long length = static_cast<unsigned long>(info[0].As<Napi::Number>().Uint32Value());
    Napi::Buffer<uint8_t> data = Napi::Buffer<uint8_t>::New(env, length);
    UseBufferData(data.Data(), length);
    return data;
}

// --- Negative control: wrong result type (Napi::TypeError::New, not Buffer) -----------------
Napi::Value WrongResultTypeTypeError(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::TypeError err = Napi::TypeError::New(env, "bad argument");
    err.ThrowAsJavaScriptException();
    return env.Undefined();
}

// --- Negative control: lookalike, unrelated namespace (Other::Buffer::New, not Napi::) ------
namespace Other {
class Buffer {
 public:
  static Buffer New(napi_env env, unsigned long length);
  unsigned char *Data() const;
};
}  // namespace Other

Napi::Value LookalikeOtherBuffer(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    unsigned long length = 4;
    Other::Buffer data = Other::Buffer::New(env, length);
    UseBufferData(data.Data(), length);
    return env.Undefined();
}

// --- Negative control: unrelated .New (a totally different, unrelated class) ----------------
class Widget {
 public:
  static Widget New(napi_env env, unsigned long length);
  unsigned char *Data() const;
};

Napi::Value UnrelatedWidgetNew(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    unsigned long length = 4;
    Widget w = Widget::New(env, length);
    UseBufferData(w.Data(), length);
    return env.Undefined();
}

// --- Negative control: Buffer::New's real 3-arg EXTERNAL-DATA overload (out of scope,
// same R02/R03/R04 boundary as node-canvas's own 3-arg case) ---------------------------------
Napi::Value ExternalDataOverload(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    unsigned long length = 4;
    unsigned char *external = GetExternalPointer();
    Napi::Buffer<uint8_t> data = Napi::Buffer<uint8_t>::New(env, external, length);
    UseBufferData(data.Data(), length);
    return data;
}

// --- Negative control: unresolved/ambiguous qualifier (auto-deduced local) -------------------
Napi::Value AutoDeducedLocal(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    unsigned long length = static_cast<unsigned long>(info[0].As<Napi::Number>().Uint32Value());
    auto data = Napi::Buffer<uint8_t>::New(env, length);
    UseBufferData(data.Data(), length);
    return data;
}
