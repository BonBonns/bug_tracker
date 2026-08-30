// BLIND TEST #2 (real npm package, NOT tuned to before this run): cartesi/rollups-ts
// (npm package @cartesi/machine), packages/machine/native/addon.cc, Machine::ReadMemory,
// pinned commit 1d0f419c7fdcb1dbaac31589990a1d946716a1d9 -- fetched and independently
// verified via raw.githubusercontent.com before writing this fixture (not taken on trust
// from any search agent's report). Selected because, unlike the first blind-test target
// (node-canvas's streamPDF, which used the 3-argument EXTERNAL-DATA overload and was
// therefore genuinely out of this contract's scope), this real site uses the exact
// 2-argument ALLOCATING overload REAL_CONTRACTS["Napi::Buffer"] curates:
// Napi::Buffer<uint8_t>::New(env, static_cast<size_t>(length)) -- with `length` supplied
// directly by the JS caller (get_u64 on info[1], only checked against SIZE_MAX, not
// against any application-level bound), the result subsequently used
// (data.Data() passed to cm_read_memory, then `data` itself returned), no IsEmpty()/
// IsExceptionPending() check anywhere near the call, no try/catch anywhere in the real
// file (grepped, zero hits), and binding.gyp explicitly defines NAPI_DISABLE_CPP_EXCEPTIONS
// (independently confirmed) -- matching this contract's own disclosed exceptions-disabled
// assumption. All statements in Machine::ReadMemory below are the real function's own
// statements, preserved verbatim; only supporting types/macros/functions are minimally
// stubbed, modeled on node-addon-api's real Env->napi_env implicit conversion, so the
// single translation unit compiles through c2cpg.

struct napi_env__;
using napi_env = napi_env__*;

namespace Napi {

class Value;

class Env {
 public:
  operator napi_env() const;
  Value Undefined() const;
};

class Value {
 public:
  Value();
};

class CallbackInfo {
 public:
  Napi::Env Env() const;
  const Value& operator[](int i) const;
};

template <typename T>
class Buffer : public Value {
 public:
  static Buffer<T> New(napi_env env, unsigned long length);
  T* Data() const;
};

class RangeError {
 public:
  static RangeError New(napi_env env, const char* msg);
  void ThrowAsJavaScriptException();
};

}  // namespace Napi

typedef int cm_error;
#define CM_ERROR_OK 0
struct cm_machine;

extern cm_error cm_read_memory(cm_machine* machine, unsigned long address, unsigned char* data, unsigned long length);
void throw_machine_error(Napi::Env env, cm_error code);

bool get_u64(Napi::Env env, const Napi::Value& value, const char* name, unsigned long* out);

#define SIZE_MAX 0xFFFFFFFFFFFFFFFFUL

#define CHECK_CM(env, call)                                            \
    do {                                                               \
        cm_error rc__ = (call);                                        \
        if (rc__ != CM_ERROR_OK) {                                     \
            throw_machine_error((env), rc__);                          \
            return (env).Undefined();                                  \
        }                                                               \
    } while (0)

class Machine {
 public:
  Napi::Value ReadMemory(const Napi::CallbackInfo& info);

 private:
  cm_machine* machine_ = nullptr;
};

Napi::Value Machine::ReadMemory(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    unsigned long address = 0;
    unsigned long length = 0;
    if (!get_u64(env, info[0], "address", &address) || !get_u64(env, info[1], "length", &length)) {
        return env.Undefined();
    }
    if (length > SIZE_MAX) {
        Napi::RangeError::New(env, "length is too large").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Buffer<unsigned char> data = Napi::Buffer<unsigned char>::New(env, static_cast<unsigned long>(length));
    CHECK_CM(env, cm_read_memory(machine_, address, data.Data(), length));
    return data;
}
