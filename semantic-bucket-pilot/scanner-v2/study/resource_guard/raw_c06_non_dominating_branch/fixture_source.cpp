// Shared minimal stub for RESOURCE-GUARD-R01 synthetic controls: real-shaped
// ScopedNativeCallFrame, using the SAME constructor signature curated in
// resource_contracts.py (the 4-arg-plus-implicit-Callable* real Hermes overload:
// Runtime*, unsigned int, Callable*, bool, HermesValue), plus a second, DELIBERATELY
// UNCURATED class (PlainBuffer) used only by the controls that must NOT be treated as a
// fallible resource (infallible RAII / unrelated same-named predicate method).
struct Runtime;
struct HermesValue {};
struct Callable {};

struct StackFramePtr {
  int& getArgRef(unsigned int i);
};

class ScopedNativeCallFrame {
  bool overflowed_;
  StackFramePtr frame_;
 public:
  ScopedNativeCallFrame(Runtime* runtime, unsigned int argCount, Callable* callee,
                         bool isConstructor, HermesValue thisArg);
  bool overflowed() const { return overflowed_; }
  StackFramePtr operator->() { return frame_; }
};

// PlainBuffer: NOT in resource_contracts.py. Real RAII, real constructor taking a size,
// but genuinely cannot fail (no predicate at all in the real class) -- used for the
// "infallible RAII object" control. Deliberately defines its OWN same-named `overflowed`
// method returning an unrelated value, to double as the "unrelated overflowed() method"
// control target: a call to PlainBuffer::overflowed() must never be treated as evidence
// for a ScopedNativeCallFrame guard, since the RECEIVER's type does not match the
// contract's class_name.
class PlainBuffer {
  int cursor_;
 public:
  PlainBuffer(unsigned int capacity);
  int overflowed() const { return cursor_; }  // unrelated: NOT a validity predicate
  int& at(unsigned int i);
};

struct Runtime {
  int raiseStackOverflow();
};


// CONTROL 6: non-dominating branch check (guard only on ONE of two paths that both reach
// the use) -- expect RESOURCE_GUARD_MISSING. Motivated RESOURCE-DOMINANCE-R01 (edge-keyed
// clearance): a node-keyed clearance would falsely treat the cond==false path (which
// directly skips the guard and merges at the same following statement) as cleared too.
int useIt(Runtime* runtime, unsigned int len, bool cond) {
  Callable* callee = 0;
  HermesValue thisArg{};
  ScopedNativeCallFrame f{runtime, len, callee, false, thisArg};
  if (cond) {
    if (f.overflowed())
      return runtime->raiseStackOverflow();
  }
  f->getArgRef(0) = 1;
  return 0;
}
