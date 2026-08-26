class A {
  value: string;
  other: string;
  setValue(v: string) { this.value = v; }
  setOther(v: string) { this.other = v; }
  readValue() { return this.value; }
}

// x may denote either a or b. Writing source through x may affect a.value,
// but it is not an exact/must flow to a.value.
function mayAliasWrite(cond: boolean, source: string) {
  const a = new A();
  const b = new A();
  let x;
  if (cond) x = a; else x = b;
  x.setValue(source);
  return a.readValue();
}

// Both branches choose a: the join should collapse back to an exact alias.
function sameAliasBothBranches(cond: boolean, source: string) {
  const a = new A();
  let x;
  if (cond) x = a; else x = a;
  x.setValue(source);
  return a.readValue();
}

// Different field: may-alias on receiver must not create a value-field flow.
function mayAliasDifferentField(cond: boolean, source: string) {
  const a = new A();
  const b = new A();
  let x;
  if (cond) x = a; else x = b;
  x.setOther(source);
  return a.readValue();
}

// A starts tainted; a conditional constant overwrite through x may or may not
// kill that state. The result must preserve both possibilities.
function mayAliasOverwrite(cond: boolean, source: string) {
  const a = new A();
  const b = new A();
  a.setValue(source);
  let x;
  if (cond) x = a; else x = b;
  x.setValue("CONST");
  return a.readValue();
}

// The read receiver itself is a may-alias join.
function mayAliasRead(cond: boolean, source: string) {
  const a = new A();
  const b = new A();
  a.setValue(source);
  b.setValue("CONST");
  let x;
  if (cond) x = a; else x = b;
  return x.readValue();
}

// Gate 14: uncertain provenance must survive ordinary wrapper returns without
// being hardened into the legacy exact return-taint channel.
function wrapMay(cond: boolean, source: string) {
  return mayAliasWrite(cond, source);
}

function wrapMay2(cond: boolean, source: string) {
  return wrapMay(cond, source);
}

function wrapExact(cond: boolean, source: string) {
  return sameAliasBothBranches(cond, source);
}

function wrapUnknown(cond: boolean, source: string) {
  return mayAliasDifferentField(cond, source);
}

// Gate 15: uncertain provenance through local assignment before return.
function wrapMayLocal(cond: boolean, source: string) {
  const y = mayAliasWrite(cond, source);
  return y;
}

// Two local aliases plus an interprocedural MAY hop.
function wrapMayLocal2(cond: boolean, source: string) {
  const y = wrapMayLocal(cond, source);
  const z = y;
  return z;
}

// UNKNOWN must survive the same local-assignment shape.
function wrapUnknownLocal(cond: boolean, source: string) {
  const y = mayAliasDifferentField(cond, source);
  return y;
}

// A MAY-producing call that is not the returned value must not taint the return.
function localUnrelated(cond: boolean, source: string) {
  const y = mayAliasWrite(cond, source);
  const z = "CONST";
  return z;
}

// Multiple definitions deliberately force Gate 15 to abstain rather than guess.
function localOverwrite(cond: boolean, source: string) {
  let y = mayAliasWrite(cond, source);
  y = "CONST";
  return y;
}
