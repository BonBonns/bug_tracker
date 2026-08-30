// R05 A/B PROOF, fixture B: BYTE-IDENTICAL call site to fixture A
// (Widget::New(env, length)) -- the ONLY change is that Widget's own overload set
// for "New" now also declares a second, template overload with a DIFFERENT arity/
// signature, mirroring node-addon-api's real ArrayBuffer::New (plain 2-arg overload
// + a separate template<typename Finalizer> 4-arg overload). The call site itself
// never uses the template overload. Prediction: this alone is enough to make the
// SAME call site (Widget::New(env, length)) fall back to <unresolvedNamespace>.

struct env_t;

class Widget {
 public:
  static Widget New(env_t* env, unsigned long length);

  template <typename Finalizer>
  static Widget New(env_t* env, void* externalData, unsigned long length,
                     Finalizer finalizeCallback);

  unsigned char* Data() const;
};

Widget MakeWidget(env_t* env, unsigned long length) {
    Widget w = Widget::New(env, length);
    return w;
}
