// R04 control 2: NAPI_DISABLE_CPP_EXCEPTIONS established (per this control's own
// build_config.json, curated separately -- Joern facts carry no preprocessor state) + a
// CORRECT IsEmpty() guard on the real, namespace-qualified Napi::Buffer<T>::New(env, len)
// acquisition. Expected: the contract IS applicable (config disabled), and the correct
// guard yields VALUE_ACQUISITION_GUARD_ESTABLISHED.
struct napi_env__;
using napi_env = napi_env__*;

namespace Napi {
class Env {};

template <typename T>
class Buffer {
 public:
  static Buffer<T> New(napi_env env, unsigned long length);
  bool IsEmpty() const;
  T* Data() const;
};
}  // namespace Napi

int useIt(napi_env env, unsigned long len) {
  Napi::Buffer<unsigned char> buf = Napi::Buffer<unsigned char>::New(env, len);
  if (buf.IsEmpty()) {
    return -1;
  }
  unsigned char* data = buf.Data();
  data[0] = 1;
  return 0;
}
