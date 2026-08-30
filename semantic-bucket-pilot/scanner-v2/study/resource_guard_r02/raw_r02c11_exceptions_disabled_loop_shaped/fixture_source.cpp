// Shared minimal stub for RESOURCE-GUARD-R02 synthetic controls: a NEUTRAL-NAMED
// STATIC_FACTORY acquisition class (FactoryResource::Acquire(ctx, size) -> isInvalid()),
// deliberately NOT named after node-addon-api's real Buffer/New/IsEmpty -- passing these
// controls demonstrates the R02 ALGORITHM generalizes structurally, not that it was tuned
// to recognize the real library's own names. Matches resource_contracts_r02.py's
// SYNTHETIC_CONTRACTS["FactoryResource"] entry exactly (2-param Acquire: Context*, size).
struct Context {};

class FactoryResource {
  bool invalid_;
 public:
  static FactoryResource Acquire(Context* ctx, unsigned long size);
  bool isInvalid() const { return invalid_; }
  int& at(unsigned long i);
};

// OtherResource: an UNRELATED, uncontracted class that also happens to define an
// Acquire()/isInvalid() method pair (same names, different result type) -- used by the
// "unrelated class" control to prove name-only matching is rejected.
class OtherResource {
  bool invalid_;
 public:
  static OtherResource Acquire(Context* ctx, unsigned long size);
  bool isInvalid() const { return invalid_; }
};


// CONTROL 11: "exceptions-disabled configuration" -- the canonical shape this contract is
// actually curated for (per resource_contracts_r02.py's applicable_exception_configuration
// citation), exercised in a loop (a different real CODE SHAPE than control 2, not just a
// duplicate) to confirm the dominance walk handles repeated acquire-check-use cycles --
// expect VALUE_ACQUISITION_GUARD_ESTABLISHED.
int useIt(Context* ctx, unsigned long size, int n) {
  int total = 0;
  for (int i = 0; i < n; ++i) {
    auto r = FactoryResource::Acquire(ctx, size);
    if (r.isInvalid())
      return -1;
    total += r.at(0);
  }
  return total;
}
