// BLIND TEST (real npm package, genuinely untouched before this run): @julusian/jpeg-turbo
// (Julusian/node-jpeg-turbo), npm registry confirmed published (v3.0.1, dist-tags.latest,
// gitHead 5e141c1c04fc6da8fb6dc756fcce73dda86c894b -- independently confirmed by fetching
// https://registry.npmjs.org/@julusian%2Fjpeg-turbo and comparing gitHead against the
// commit read below), src/decompress.cc, DecompressInner, pinned to that exact commit.
// Real code preserved statement-for-statement for the acquisition path (comments describing
// simplifications noted inline); minimal stub types only.
//
// Disclosed caveats identified and independently verified BEFORE running this fixture
// through the pipeline (per the required blind-test sequence):
// 1. This uses the correct, curated 2-argument allocating overload
//    (Napi::Buffer<unsigned char>::New(env, targetSize)) -- unlike node-canvas (3-arg,
//    disqualified) and matches Cartesi's own already-corrected shape.
// 2. targetSize = resWidth * resHeight * bpp is NOT a literal -- resWidth/resHeight are
//    decoded out of the attacker-supplied JPEG file's own header via tjDecompressHeader(),
//    an out-parameter call (&props.resWidth, &props.resHeight) -- the SAME data-flow
//    pattern (out-parameter, not lhs=rhs assignment) that made Cartesi's own
//    attacker_influence_evidence field absent from its finding; the same absence is
//    expected and disclosed here, not a new defect.
// 3. No IsEmpty()/IsExceptionPending() guard exists on the RESULT of New() anywhere in this
//    function. The one IsEmpty() call in the real function checks the PRE-EXISTING
//    (possibly caller-supplied, possibly default-empty) dstBuffer variable BEFORE
//    acquisition, to decide WHETHER to allocate at all -- not a post-acquisition failure
//    check on the newly allocated buffer. This is a structurally different real-world
//    pattern from any of R02/R03's synthetic controls (a predicate on the SAME variable
//    NAME, but occurring BEFORE the acquisition it superficially appears to guard).
// 4. Exceptions build configuration is NOT confirmed disabled for this project (unlike
//    Cartesi, which explicitly defined NAPI_DISABLE_CPP_EXCEPTIONS). Neither
//    NAPI_CPP_EXCEPTIONS nor NAPI_DISABLE_CPP_EXCEPTIONS appears anywhere in this project's
//    real CMakeLists.txt (independently verified), and no -fno-exceptions/-fexceptions
//    override is set either. Per node-addon-api's own real napi.h default-resolution logic
//    (independently confirmed from nodejs/node-addon-api's real source): when neither macro
//    is set, exceptions are enabled if the COMPILER was built with exceptions on (the
//    near-universal C++ default, absent an explicit -fno-exceptions). This project most
//    likely builds with C++ exceptions ENABLED BY DEFAULT -- the OPPOSITE of this
//    contract's own disclosed "exceptions_disabled" assumption. This is a real, material
//    mismatch, disclosed here BEFORE running the pipeline, not discovered after.

struct napi_env__;
using napi_env = napi_env__*;

namespace Napi {

class Value;

class Env {
 public:
  operator napi_env() const;
  Value Undefined() const;
  Value Null() const;
};

class Value {
 public:
  Value();
  bool IsBuffer() const;
  bool IsObject() const;
  template <typename T>
  T As() const;
};

class Object : public Value {
 public:
  Value Get(const char* key) const;
};

class Number : public Value {
 public:
  unsigned int Uint32Value() const;
};

class CallbackInfo {
 public:
  Napi::Env Env() const;
  int Length() const;
  const Value& operator[](int i) const;
};

template <typename T>
class Buffer : public Value {
 public:
  Buffer();
  static Buffer<T> New(napi_env env, unsigned long length);
  bool IsEmpty() const;
  unsigned long Length() const;
  T* Data() const;
};

class TypeError {
 public:
  static TypeError New(napi_env env, const char* msg);
  void ThrowAsJavaScriptException();
};

}  // namespace Napi

// Minimal stand-ins for the real libjpeg-turbo/handle plumbing -- not the point of this
// fixture, which targets only the Buffer<T>::New acquisition and its guard.
typedef void* tjhandle;
tjhandle tjInitDecompress();
void tjDestroy(tjhandle handle);
const char* tjGetErrorStr();
int tjDecompressHeader(tjhandle handle, const unsigned char* srcData, unsigned long srcLength,
                        int* width, int* height);

struct DecompressProps {
  tjhandle handle;
  const unsigned char* srcData;
  unsigned long srcLength;
  int resWidth;
  int resHeight;
  int bpp;
  unsigned long resSize;
  unsigned char* resData;
};

// Real function body, preserved statement-for-statement for the acquisition path (the
// options-parsing/format-switch block, present in the real function, is collapsed to a
// fixed bpp here -- it does not affect the acquisition/guard shape under test).
Napi::Value DecompressInner(const Napi::CallbackInfo& info, bool async) {
  Napi::Env env = info.Env();

  if (info.Length() < 1) {
    Napi::TypeError::New(env, "Not enough arguments").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Invalid source buffer").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<unsigned char> srcBuffer = info[0].As<Napi::Buffer<unsigned char>>();

  Napi::Buffer<unsigned char> dstBuffer;
  if (info[1].IsBuffer()) {
    dstBuffer = info[1].As<Napi::Buffer<unsigned char>>();
    if (dstBuffer.Length() == 0) {
      Napi::TypeError::New(env, "Invalid destination buffer").ThrowAsJavaScriptException();
      return env.Null();
    }
  }

  DecompressProps props = {};
  props.srcData = srcBuffer.Data();
  props.srcLength = srcBuffer.Length();
  props.bpp = 4;

  tjhandle handle = tjInitDecompress();
  if (handle == nullptr) {
    Napi::TypeError::New(env, tjGetErrorStr()).ThrowAsJavaScriptException();
    return env.Null();
  }
  props.handle = handle;

  int err = tjDecompressHeader(handle, props.srcData, props.srcLength, &props.resWidth, &props.resHeight);
  if (err != 0) {
    tjDestroy(handle);
    Napi::TypeError::New(env, tjGetErrorStr()).ThrowAsJavaScriptException();
    return env.Null();
  }

  auto targetSize = static_cast<unsigned long>(props.resWidth) * props.resHeight * props.bpp;
  if (dstBuffer.IsEmpty()) {
    dstBuffer = Napi::Buffer<unsigned char>::New(env, targetSize);
  }

  props.resSize = targetSize;
  props.resData = dstBuffer.Data();

  if (targetSize > dstBuffer.Length()) {
    tjDestroy(handle);
    Napi::TypeError::New(env, "Insufficient output buffer").ThrowAsJavaScriptException();
    return env.Null();
  }

  tjDestroy(handle);
  return dstBuffer;
}
