// Real exports.Set(Napi::String::New(...), Napi::Function::New(...)) registration idiom,
// matching this project's own documented measurement (module docstring: "shape MEASURED
// on real c2cpg output of node.bcrypt.js"). Registers Foo/Bar/Baz -- matching the JS-side
// controls' own real call names.
#include <napi.h>

Napi::Value Foo(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 1);
}

Napi::Value Bar(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 2);
}

Napi::Value Baz(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 3);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "Foo"), Napi::Function::New(env, Foo));
  exports.Set(Napi::String::New(env, "Bar"), Napi::Function::New(env, Bar));
  exports.Set(Napi::String::New(env, "Baz"), Napi::Function::New(env, Baz));
  return exports;
}

NODE_API_MODULE(addon, Init)
