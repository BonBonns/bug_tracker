// Real exports.Set(Napi::String::New(...), Napi::Function::New(...)) registration idiom,
// matching this project's own documented measurement (module docstring: "shape MEASURED
// on real c2cpg output of node.bcrypt.js"). Registers Foo/Bar/Baz/Qux -- matching the
// JS-side controls' own real call names (Qux added for CROSSLANG-LINK-FIX01D's
// double-quoted require() positive control).
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

Napi::Value Qux(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 4);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "Foo"), Napi::Function::New(env, Foo));
  exports.Set(Napi::String::New(env, "Bar"), Napi::Function::New(env, Bar));
  exports.Set(Napi::String::New(env, "Baz"), Napi::Function::New(env, Baz));
  exports.Set(Napi::String::New(env, "Qux"), Napi::Function::New(env, Qux));
  return exports;
}

NODE_API_MODULE(addon, Init)
