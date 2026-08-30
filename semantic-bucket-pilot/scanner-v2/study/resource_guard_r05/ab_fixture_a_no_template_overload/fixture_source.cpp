// R05 A/B PROOF, fixture A: a static factory whose NAME's overload set contains NO
// template overload. Real, minimal, compiles standalone with a real C++17 compiler
// (see BUILD.md in this directory for the exact command used to verify that).
// Prediction: Widget::New(env, length) resolves to a real, qualified methodFullName.

struct env_t;

class Widget {
 public:
  static Widget New(env_t* env, unsigned long length);
  unsigned char* Data() const;
};

Widget MakeWidget(env_t* env, unsigned long length) {
    Widget w = Widget::New(env, length);
    return w;
}
