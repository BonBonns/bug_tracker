// Isolates: an #ifndef/#endif-guarded block inside the class body, wrapping a
// TEMPLATE second overload -- the EXACT structural pattern real napi.h uses for
// both Napi::Buffer<T> and Napi::ArrayBuffer.
struct env_t;

class Widget {
 public:
  static Widget New(env_t* env, unsigned long length);
#ifndef WIDGET_NO_EXTERNAL_DATA
  static Widget New(env_t* env, void* externalData, unsigned long length);

  template <typename Finalizer>
  static Widget New(env_t* env, void* externalData, unsigned long length,
                     Finalizer finalizeCallback);
#endif
  unsigned char* Data() const;
};

Widget MakeWidget(env_t* env, unsigned long length) {
    Widget w = Widget::New(env, length);
    return w;
}
