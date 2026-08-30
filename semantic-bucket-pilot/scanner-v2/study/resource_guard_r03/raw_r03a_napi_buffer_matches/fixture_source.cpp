// R03 namespace-discrimination control A: a real-shaped, correctly-namespaced
// Napi::Buffer<T>::New(env, length) call (the exact contract this correction targets),
// with an EXPLICIT declared type (matching real node-addon-api usage, e.g. cartesi's
// `Napi::Buffer<uint8_t> data = Napi::Buffer<uint8_t>::New(...)` -- NOT `auto`, which was
// found to resolve to a NAMESPACE-QUALIFIED type_full_name ("Napi.Buffer") rather than the
// bare "Buffer" an explicit declaration resolves to; result_type stays bare "Buffer" per
// that real, confirmed asymmetry). UNGUARDED. Expected under --real (REAL_CONTRACTS,
// corrected qualifier_type = "Napi.Buffer"): the call IS matched (ACQUISITION_SIGNATURE_
// UNRECOGNIZED must NOT fire), and the unguarded use produces VALUE_ACQUISITION_GUARD_MISSING.
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

void useIt(napi_env env, unsigned long len) {
  Napi::Buffer<unsigned char> buf = Napi::Buffer<unsigned char>::New(env, len);
  unsigned char* data = buf.Data();
  data[0] = 1;
}
