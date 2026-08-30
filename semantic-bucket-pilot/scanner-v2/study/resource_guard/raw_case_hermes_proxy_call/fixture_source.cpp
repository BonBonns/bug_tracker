// GENERALIZATION CHECK (not a vulnerability): real facebook/hermes lib/VM/JSCallableProxy.cpp,
// revision 82f0f971 -- the SAME vulnerable/patched revision as CVE-2020-1896's own
// hermesBuiltinApply, era-matched (same ScopedNativeCallFrame API, Runtime* not Runtime&).
// A DIFFERENT real call site of the SAME curated class: the size argument comes from
// callerFrame.getArgCount() (the CALLER's own current frame, not a JS array's .length),
// and the USE is std::uninitialized_copy_n over getArgRefUnsafe(0), not a manual per-index
// getArgRef loop. Correctly guarded in the real code (never the CVE-2020-1896 bug) -- used
// here ONLY to check whether the general algorithm recognizes ESTABLISHED on real code with
// a different attacker-influence source and a different use shape, not to claim a second
// real vulnerability. The constructor call, guard, and copy statement are copied VERBATIM;
// surrounding machinery (JSCallableProxy's own slots/trap lookup) is stubbed to the minimum
// needed to parse.
struct Runtime;
struct HermesValue {
  static HermesValue encodeUndefinedValue();
};
struct Callable {};

struct StackFramePtr {
  bool isConstructorCall();
  unsigned int getArgCount();
  HermesValue getNewTargetRef();
  HermesValue getThisArgRef();
  HermesValue& getArgRefUnsafe(unsigned int i);
};

class ScopedNativeCallFrame {
  bool overflowed_;
  StackFramePtr frame_;
 public:
  ScopedNativeCallFrame(Runtime* runtime, unsigned int argCount, HermesValue callee,
                         HermesValue newTarget, HermesValue thisArg);
  bool overflowed() const { return overflowed_; }
  StackFramePtr operator->() { return frame_; }
};

enum class ExecutionStatus { EXCEPTION, RETURNED };
template <typename T = HermesValue>
struct CallResult {
  CallResult(ExecutionStatus s);
  CallResult(T v);
};

struct Runtime {
  enum class StackOverflowKind { JSRegisterStack, NativeStack };
  CallResult<HermesValue> raiseStackOverflow(StackOverflowKind kind);
  StackFramePtr getCurrentFrame();
};

namespace std {
template <typename I, typename N, typename O>
O uninitialized_copy_n(I first, N n, O out);
}

// Real code (JSCallableProxy.cpp::_proxyNativeCall, the no-trap forward-call branch): build
// a native call frame sized by the CALLER's own argument count, and forward the caller's
// arguments into it via std::uninitialized_copy_n over getArgRefUnsafe(0).
CallResult<HermesValue> proxyForwardCall(
    Runtime* runtime, StackFramePtr callerFrame, HermesValue target) {
  HermesValue newTarget = callerFrame.isConstructorCall()
      ? callerFrame.getNewTargetRef()
      : HermesValue::encodeUndefinedValue();
  ScopedNativeCallFrame newFrame{runtime,
                                 callerFrame.getArgCount(),
                                 target,
                                 newTarget,
                                 callerFrame.getThisArgRef()};
  if (newFrame.overflowed())
    return runtime->raiseStackOverflow(
        Runtime::StackOverflowKind::NativeStack);
  std::uninitialized_copy_n(
      &(callerFrame.getArgRefUnsafe(0)),
      callerFrame.getArgCount(),
      &(newFrame->getArgRefUnsafe(0)));
  return ExecutionStatus::RETURNED;
}
