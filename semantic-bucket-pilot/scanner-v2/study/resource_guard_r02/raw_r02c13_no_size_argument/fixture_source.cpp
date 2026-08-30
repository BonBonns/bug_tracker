// CONTROL 13: factory called via an overload WITHOUT the contract's own curated (2-param,
// size-bearing) signature -- expect VALUE_ACQUISITION_SEMANTICS_UNRESOLVED
// (ACQUISITION_SIGNATURE_PARAM_COUNT_UNRECOGNIZED): the class/method NAME matches
// ("FactoryResource"/"Acquire"), but this specific overload's own methodFullName has a
// DIFFERENT parameter count than any curated result_mfn_prefixes entry, so it must never
// be assumed to still carry a size at the same curated index. Standalone (not using
// common_stub.h) so the SAME class can define both the curated 2-param overload (unused
// here, just present to make the "same class, different overload" shape realistic) and
// the uncurated 1-param one actually called.
struct Context {};

class FactoryResource {
  bool invalid_;
 public:
  static FactoryResource Acquire(Context* ctx, unsigned long size);  // the curated overload
  static FactoryResource Acquire(Context* ctx);  // NOT curated -- no size parameter at all
  bool isInvalid() const { return invalid_; }
  int& at(unsigned long i);
};

int useIt(Context* ctx) {
  auto r = FactoryResource::Acquire(ctx);
  return r.isInvalid();
}
