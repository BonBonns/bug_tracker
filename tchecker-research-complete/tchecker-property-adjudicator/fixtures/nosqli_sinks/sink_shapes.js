// NoSQL injection sink-semantics characterization. Property:
// ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE -- does attacker-controlled input reach a MongoDB
// query FIELD VALUE position without being constrained to a primitive (non-object) type, enabling
// operator injection ($ne, $regex, $gt, $where, etc.)? Each function isolates ONE call shape,
// matching real patterns from RocketChat's own disclosed NoSQL injection history (CVE-2021-22911's
// getPasswordPolicy/token field, HackerOne #3564655's access_token field, GHSA-hgq6-9jg2-wf3f's
// username field). No property-effect (type-guard) logic here -- pure sink/operand identification.
const Meteor = { methods: (obj) => obj };

// --- findOne with a single field, attacker value directly as the field's value (the exact real
// shape from GHSA-hgq6-9jg2-wf3f: username used directly in a findOne selector) ---
async function findOneSingleField(username) {
  return Users.findOne({ username });
}

// --- findOne with the field value from a shorthand-equivalent explicit key:value form (the exact
// real shape from CVE-2021-22911's getPasswordPolicy: token used directly) ---
async function findOneExplicitKeyValue(token) {
  return Users.findOne({ 'services.password.reset.token': token });
}

// --- find() (returns a cursor/multiple docs) -- same selector-object shape ---
async function findMultiple(userId) {
  return Messages.find({ userId });
}

// --- updateOne: the SELECTOR (first arg) matters for this property; the update document (second
// arg) is a structurally different position, not the injection-relevant one for THIS property ---
async function updateOneSelector(recordId, newValue) {
  return Records.updateOne({ _id: recordId }, { $set: { value: newValue } });
}

// --- deleteOne: single-argument selector shape ---
async function deleteOneSelector(sessionId) {
  return Sessions.deleteOne({ sessionId });
}

// --- countDocuments: same selector shape, different terminal operation ---
async function countDocumentsSelector(status) {
  return Orders.countDocuments({ status });
}

// --- multiple fields in one selector -- each field value is its OWN operand, must be tracked
// independently (mirrors SSRF's per-operand tracking discipline) ---
async function findOneMultipleFields(email, active) {
  return Users.findOne({ email, active: true, statusFlag: active });
}

// --- the field itself (not just the value) is attacker-influenced -- a structurally DIFFERENT,
// arguably worse shape (computed/dynamic key), analogous to SSRF's "attacker controls the pattern
// itself" distinction -- must be identified separately, not conflated with value-only control ---
async function attackerControlsFieldName(fieldName, fieldValue) {
  return Users.findOne({ [fieldName]: fieldValue });
}

Meteor.methods({
  findOneSingleField, findOneExplicitKeyValue, findMultiple, updateOneSelector,
  deleteOneSelector, countDocumentsSelector, findOneMultipleFields, attackerControlsFieldName,
});
