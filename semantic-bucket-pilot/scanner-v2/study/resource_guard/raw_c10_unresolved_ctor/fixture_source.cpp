// CONTROL 10: unresolved constructor semantics -- a class sharing the contracted NAME
// but with an unrecognized signature (no size argument at all) -- expect
// RESOURCE_SEMANTICS_UNRESOLVED, never a guess.
struct Runtime { int raiseStackOverflow(); };

class ScopedNativeCallFrame {
 public:
  ScopedNativeCallFrame(Runtime* runtime);
  bool overflowed() const;
  int& operator*();
};

int useIt(Runtime* runtime) {
  ScopedNativeCallFrame f{runtime};
  return f.overflowed();
}
