// C8: exported instance method's own parameter through an unknown member-method
// transform -- abstain (OPEN/CANDIDATE_OPEN), same shape as demo_member_transform.js
// but sourced from PACKAGE_API_INPUT instead of APPLICATION_INGRESS_INPUT.
class Processor {
  redact(input) {
    const clone = { ...input };
    delete clone['password'];
    return clone;
  }
  process(input) {
    const cleaned = this.redact(input);
    return JSON.stringify(cleaned);
  }
}
module.exports = Processor;
