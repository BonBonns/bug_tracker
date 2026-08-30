// CVE-2020-1896: Hermes hermesBuiltinApply, vulnerable revision 82f0f971 (parent of the
// real fix commit 86543ac47e59c522976b5632b8bf9a2a4583c7d2). Real function body below is
// copied verbatim from lib/VM/JSLib/HermesBuiltin.cpp at that revision; everything else in
// this file is a minimal type-shape stub (real member/method names and signatures, taken
// from include/hermes/VM/Runtime.h at the same revision) so a single-TU c2cpg export can
// parse the real function without pulling in the whole Hermes build.
#define LLVM_UNLIKELY(x) (x)

enum class ExecutionStatus { EXCEPTION, RETURNED };

struct HermesValue {
  static HermesValue encodeNumberValue(double d);
  static HermesValue encodeObjectValue(void* p);
  static HermesValue encodeUndefinedValue();
  double getNumber();
};

struct Runtime;

template <typename T = HermesValue>
struct CallResult {
  CallResult(ExecutionStatus s);
  CallResult(T v);
  bool operator==(ExecutionStatus s);
  T operator*();
};

struct Callable {
  static CallResult<HermesValue> createThisForConstruct(void* fn, Runtime* runtime);
  static CallResult<HermesValue> construct(void* fn, Runtime* runtime, HermesValue thisVal);
  static CallResult<HermesValue> call(void* fn, Runtime* runtime);
};

struct JSArray {
  static unsigned int getLength(JSArray* arr);
  HermesValue at(Runtime* runtime, unsigned int i);
};

template <typename T>
struct Handle {
  T* operator*();
  T* operator->();
  operator bool();
};

template <typename T = HermesValue>
struct MutableHandle {
  MutableHandle(Runtime* runtime);
  MutableHandle<T>& operator=(HermesValue v);
  HermesValue getHermesValue();
};

struct NativeArgs {
  template <typename T>
  Handle<T> dyncastArg(unsigned int index);
  Handle<HermesValue> getArgHandle(unsigned int index);
  HermesValue getArg(unsigned int index);
  unsigned int getArgCount();
};

struct StackFramePtr {
  HermesValue& getArgRef(unsigned int i);
};

// Real shape (Runtime.h): ScopedNativeCallFrame allocates `registersNeeded` slots on the
// runtime's bounded register stack via allocUninitializedStack(); if that allocation would
// overflow the stack, the constructor sets overflowed_ and returns WITHOUT allocating a
// frame_ -- the caller MUST check overflowed() before touching the frame via operator->.
class ScopedNativeCallFrame {
  bool overflowed_;
  StackFramePtr frame_;

 public:
  ScopedNativeCallFrame(Runtime* runtime, unsigned int argCount, HermesValue callee,
                         bool isConstructor, HermesValue thisArg);
  bool overflowed() const { return overflowed_; }
  StackFramePtr operator->() { return frame_; }
};

struct GCScopeMarkerRAII {
  GCScopeMarkerRAII(Runtime* runtime);
};

struct Runtime {
  CallResult<HermesValue> raiseTypeErrorForValue(Handle<HermesValue> v, const char* msg);
  CallResult<HermesValue> raiseTypeError(const char* msg);
};

/// \code
///   HermesBuiltin.apply = function(fn, argArray, thisVal(opt)) {}
/// /endcode
/// Faster version of Function.prototype.apply which does not use its `this`
/// argument.
/// `argArray` must be a JSArray with no getters.
/// Equivalent to fn.apply(thisVal, argArray) if thisVal is provided.
/// If thisVal is not provided, equivalent to running `new fn` and passing the
/// arguments in argArray.
CallResult<HermesValue>
hermesBuiltinApply(void *, Runtime *runtime, NativeArgs args) {
  GCScopeMarkerRAII marker{runtime};

  Handle<Callable> fn = args.dyncastArg<Callable>(0);
  if (LLVM_UNLIKELY(!fn)) {
    return runtime->raiseTypeErrorForValue(
        args.getArgHandle(0), " is not a function");
  }

  Handle<JSArray> argArray = args.dyncastArg<JSArray>(1);
  if (LLVM_UNLIKELY(!argArray)) {
    return runtime->raiseTypeError("args must be an array");
  }

  unsigned int len = JSArray::getLength(*argArray);

  bool isConstructor = args.getArgCount() == 2;

  MutableHandle<> thisVal{runtime};
  if (isConstructor) {
    auto thisValRes = Callable::createThisForConstruct(fn, runtime);
    if (LLVM_UNLIKELY(thisValRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    thisVal = *thisValRes;
  } else {
    thisVal = args.getArg(2);
  }

  ScopedNativeCallFrame newFrame{
      runtime, len, *fn, isConstructor, thisVal.getHermesValue()};
  for (unsigned int i = 0; i < len; ++i) {
    newFrame->getArgRef(i) = argArray->at(runtime, i);
  }
  return isConstructor ? Callable::construct(fn, runtime, thisVal)
                       : Callable::call(fn, runtime);
}
