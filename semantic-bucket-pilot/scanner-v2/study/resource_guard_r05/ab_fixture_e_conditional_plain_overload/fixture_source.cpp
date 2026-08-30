// Isolates: an #ifndef/#endif-guarded block inside the class body, wrapping a
// PLAIN (non-template) second overload -- mirrors real napi.h's structural
// pattern (#ifndef NODE_API_NO_EXTERNAL_BUFFERS_ALLOWED) minus the template.
struct env_t;

class Widget {
 public:
  static Widget New(env_t* env, unsigned long length);
#ifndef WIDGET_NO_EXTERNAL_DATA
  static Widget New(env_t* env, void* externalData, unsigned long length);
#endif
  unsigned char* Data() const;
};

Widget MakeWidget(env_t* env, unsigned long length) {
    Widget w = Widget::New(env, length);
    return w;
}
