// GENERALIZATION CHECK (not a vulnerability): real facebook/hermes lib/VM/JSLib/RegExp.cpp,
// revision 82f0f971 -- the SAME vulnerable/patched revision as CVE-2020-1896's own
// hermesBuiltinApply, era-matched (same ScopedNativeCallFrame API, Runtime* not Runtime&).
// A DIFFERENT real call site of the SAME curated class: the constructor's size argument is
// a COMPUTED ARITHMETIC EXPRESSION (1 + nCaptures + 2, nCaptures derived from the regex
// pattern's own capture-group count -- attacker-influenced via the regex literal, not via a
// JSArray length), not a bare identifier; the USE is a for-loop writing each capture group
// via getArgRef, not a single indexed write. Correctly guarded in the real code (never the
// CVE-2020-1896 bug) -- used here ONLY to check whether the general algorithm recognizes
// ESTABLISHED on real code with a different size-expression shape and a loop-shaped use, not
// to claim a second real vulnerability. The constructor call, guard, and the first line of
// the fill loop are copied VERBATIM; surrounding machinery (Handle<>, capturesHandle,
// ArrayStorage) is stubbed to the minimum needed to parse.
struct Runtime;
struct HermesValue {
  static HermesValue encodeUndefinedValue();
};
struct StringPrimitive {};

template <typename T>
struct Handle {
  T* operator*();
  HermesValue getHermesValue();
};

struct ArrayStorageHandle {
  unsigned int size();
  HermesValue at(unsigned int i);
};

struct StackFramePtr {
  HermesValue& getArgRef(unsigned int i);
};

class ScopedNativeCallFrame {
  bool overflowed_;
  StackFramePtr frame_;
 public:
  ScopedNativeCallFrame(Runtime* runtime, unsigned int argCount, HermesValue callee,
                         bool isConstructor, HermesValue thisArg);
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
};

// Real code (RegExp.cpp, the functionalReplace branch of the regex-replace algorithm):
// build a native call frame sized by 1 (matched) + the regex's own capture-group count +
// 2 (position, subject string), attacker-influenced via the regex pattern's capture-group
// count, and fill it with the match's captured groups via a loop -- a different USE shape
// than hermesBuiltinApply's single indexed write.
CallResult<HermesValue> buildReplacerArgs(
    Runtime* runtime, Handle<StringPrimitive> matched, ArrayStorageHandle* capturesHandle,
    unsigned int nCaptures, HermesValue replaceFn) {
  unsigned int replacerArgsCount = 1 + nCaptures + 2;
  ScopedNativeCallFrame newFrame{runtime,
                                 replacerArgsCount,
                                 replaceFn,
                                 false,
                                 HermesValue::encodeUndefinedValue()};
  if (newFrame.overflowed())
    return runtime->raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);

  unsigned int argIdx = 0;
  newFrame->getArgRef(argIdx++) = matched.getHermesValue();
  for (; argIdx <= capturesHandle->size(); ++argIdx) {
    newFrame->getArgRef(argIdx) = capturesHandle->at(argIdx - 1);
  }
  return ExecutionStatus::RETURNED;
}
