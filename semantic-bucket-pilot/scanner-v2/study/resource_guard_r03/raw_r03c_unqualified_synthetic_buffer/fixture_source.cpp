// R03 namespace-discrimination control C: an UNQUALIFIED (global-scope, no namespace)
// Buffer::New(...) call -- structurally identical to the real contract's call shape, but
// deliberately NOT node-addon-api's real namespaced form. Explicit declared type, matching
// control A. Expected under the SYNTHETIC pool (no --real): matches R03's own separate,
// explicitly-decoupled synthetic "Buffer" contract (qualifier_type "Buffer", unnamespaced)
// -- NOT the real Napi::Buffer contract, which is never consulted in this run. Expected
// under --real (a second run of the SAME fixture): rejected via
// ACQUISITION_SIGNATURE_UNRECOGNIZED, since the real contract's qualifier is "Napi.Buffer",
// not "Buffer" -- confirming pool separation holds in both directions.
struct napi_env__;
using napi_env = napi_env__*;

class Env {};

template <typename T>
class Buffer {
 public:
  static Buffer<T> New(napi_env env, unsigned long length);
  bool IsEmpty() const;
  T* Data() const;
};

void useIt(napi_env env, unsigned long len) {
  Buffer<unsigned char> buf = Buffer<unsigned char>::New(env, len);
  unsigned char* data = buf.Data();
  data[0] = 1;
}
