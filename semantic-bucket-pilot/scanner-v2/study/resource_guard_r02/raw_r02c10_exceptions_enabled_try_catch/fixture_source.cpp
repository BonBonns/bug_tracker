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


// CONTROL 10: "exceptions-enabled configuration" -- a REAL try/catch visibly wraps the
// acquisition+use, with NO isInvalid() check at all. Under a genuinely exceptions-enabled
// build, the real node-addon-api contract this fixture is modeled on would THROW on
// failure rather than return an invalid result, making the missing isInvalid() check a
// non-issue -- but this project's exported CPG facts (calls/cfg_edges/locals/...) carry
// NO representation of try/catch AST structure or preprocessor state at all (confirmed by
// inspecting export_c_cpp_facts_v03.sc's own field list). This control PROVES, empirically,
// that R02 cannot see or use the try/catch as a safety signal -- expect
// VALUE_ACQUISITION_GUARD_MISSING (same as if the try/catch were not there at all), which
// is the exact, disclosed limitation applicable_exception_configuration exists to name
// rather than hide.
int useIt(Context* ctx, unsigned long size) {
  try {
    auto r = FactoryResource::Acquire(ctx, size);
    r.at(0) = 1;
  } catch (...) {
    return -1;
  }
  return 0;
}
