// R03 namespace-discrimination control B: same class name ("Buffer"), same method name
// ("New"), same 2-argument arity as the real Napi::Buffer contract, but under a DIFFERENT
// namespace ("Other", not "Napi"). Explicit declared type, matching control A. Expected
// under --real: rejected via ACQUISITION_SIGNATURE_UNRECOGNIZED -- the qualifier
// "Other.Buffer.New:" does not match the contract's "Napi.Buffer.New:" prefix. Zero findings.
struct napi_env__;
using napi_env = napi_env__*;

namespace Other {
class Env {};

template <typename T>
class Buffer {
 public:
  static Buffer<T> New(napi_env env, unsigned long length);
  bool IsEmpty() const;
  T* Data() const;
};
}  // namespace Other

void useIt(napi_env env, unsigned long len) {
  Other::Buffer<unsigned char> buf = Other::Buffer<unsigned char>::New(env, len);
  unsigned char* data = buf.Data();
  data[0] = 1;
}
