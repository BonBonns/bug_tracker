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


// CONTROL 2: correct IsEmpty()-shaped (isInvalid()) failure guard, terminating -- expect
// VALUE_ACQUISITION_GUARD_ESTABLISHED.
int useIt(Context* ctx, unsigned long size) {
  auto r = FactoryResource::Acquire(ctx, size);
  if (r.isInvalid())
    return -1;
  r.at(0) = 1;
  return 0;
}
