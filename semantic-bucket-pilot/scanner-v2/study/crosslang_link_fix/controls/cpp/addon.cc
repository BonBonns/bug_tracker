// Real exports.Set(Napi::String::New(...), Napi::Function::New(...)) registration idiom,
// matching this project's own documented measurement (module docstring: "shape MEASURED
// on real c2cpg output of node.bcrypt.js"). Registers Foo/Bar/Baz/Qux/Quux/Corge/Grault/
// Garply -- matching the JS-side controls' own real call names (Quux/Corge/Grault/Garply
// added for CROSSLANG-LINK-FIX01E's template-literal/whitespace/aliased-loader positive
// controls; the bare-helper negatives never register anything here on purpose -- they
// must be rejected before ever reaching a name lookup).
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

Napi::Value Quux(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 5);
}

Napi::Value Corge(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 6);
}

Napi::Value Grault(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 7);
}

Napi::Value Garply(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, 8);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "Foo"), Napi::Function::New(env, Foo));
  exports.Set(Napi::String::New(env, "Bar"), Napi::Function::New(env, Bar));
  exports.Set(Napi::String::New(env, "Baz"), Napi::Function::New(env, Baz));
  exports.Set(Napi::String::New(env, "Qux"), Napi::Function::New(env, Qux));
  exports.Set(Napi::String::New(env, "Quux"), Napi::Function::New(env, Quux));
  exports.Set(Napi::String::New(env, "Corge"), Napi::Function::New(env, Corge));
  exports.Set(Napi::String::New(env, "Grault"), Napi::Function::New(env, Grault));
  exports.Set(Napi::String::New(env, "Garply"), Napi::Function::New(env, Garply));
  return exports;
}

NODE_API_MODULE(addon, Init)
