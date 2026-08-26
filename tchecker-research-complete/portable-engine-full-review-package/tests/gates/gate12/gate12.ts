class A {
  value: string;
  other: string;
  setValue(v: string) { this.value = v; }
  setOther(v: string) { this.other = v; }
  readValue() { return this.value; }
  readOther() { return this.other; }
}

class Holder { worker: A; }

// Alias chain through the same receiver/property identity.
function aliasSame(h: Holder, source: string) {
  const x = h.worker;
  const y = x;
  y.setValue(source);
  return h.worker.readValue();
}

// Same allocation, two local aliases.
function aliasAllocation(source: string) {
  const a = new A();
  const x = a;
  const y = x;
  y.setValue(source);
  return a.readValue();
}

// Alias survives a later exact overwrite; source must be killed.
function aliasOverwrite(source: string) {
  const a = new A();
  const x = a;
  const y = x;
  x.setValue(source);
  y.setValue("CONST");
  return a.readValue();
}

// Same property name on a distinct allocation must not cross-flow.
function aliasDistinct(source: string) {
  const a = new A();
  const b = new A();
  const x = a;
  const y = b;
  y.setValue(source);
  return x.readValue();
}

// Same receiver alias but a different field must not cross-flow.
function aliasDifferentField(source: string) {
  const a = new A();
  const x = a;
  x.setOther(source);
  return a.readValue();
}

// Two object parameters are distinct identities unless the frontend proves aliasing.
function aliasDifferentParams(h: Holder, other: Holder, source: string) {
  const x = h.worker;
  const y = other.worker;
  y.setValue(source);
  return x.readValue();
}
