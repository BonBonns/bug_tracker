namespace NS {
struct env_t;

class Widget {
 public:
  static Widget New(env_t* env, unsigned long length);
  unsigned char* Data() const;
};
}  // namespace NS

NS::Widget MakeWidget(NS::env_t* env, unsigned long length) {
    NS::Widget w = NS::Widget::New(env, length);
    return w;
}
