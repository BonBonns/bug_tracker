// R03 namespace-discrimination control E: a global-scope class literally named "NapiBuffer"
// (concatenated, no namespace separator) with a same-named "New" method of identical
// 2-argument arity -- chosen specifically to catch a LOOSE/substring-based qualifier check
// (e.g. "contains Napi" or "endswith Buffer") that an exact-prefix check must reject.
// Explicit declared type, matching control A. The real, resolved methodFullName is
// "NapiBuffer.New:NapiBuffer(napi_env__*,long)", which does NOT start with the contract's
// exact qualified prefix "Napi.Buffer.New:" (the literal dot after "Napi" is significant
// and absent here). Expected under --real: ACQUISITION_SIGNATURE_UNRECOGNIZED, zero findings.
struct napi_env__;
using napi_env = napi_env__*;

class NapiBuffer {
 public:
  static NapiBuffer New(napi_env env, unsigned long length);
  bool IsEmpty() const;
  unsigned char* Data() const;
};

void useIt(napi_env env, unsigned long len) {
  NapiBuffer buf = NapiBuffer::New(env, len);
  unsigned char* data = buf.Data();
  data[0] = 1;
}
