class A {
  value: string;
  other: string;

  setValue(v: string) { this.value = v; }
  setOther(v: string) { this.other = v; }
  readValue() { return this.value; }
  readOther() { return this.other; }
}

class Holder { worker: A; }

function store(h: Holder, input: string) {
  h.worker.setValue(input);
}

function load(h: Holder) {
  return h.worker.readValue();
}

function topState(h: Holder, source: string) {
  store(h, source);
  return load(h);
}

function topConstantOverwrite(h: Holder, source: string) {
  store(h, source);
  store(h, "CONST");
  return load(h);
}

function directState(h: Holder, source: string) {
  h.worker.setValue(source);
  return h.worker.readValue();
}

function directConstant(h: Holder, source: string) {
  h.worker.setValue("CONST");
  return h.worker.readValue();
}

function differentField(h: Holder, source: string) {
  h.worker.setOther(source);
  return h.worker.readValue();
}

function twoObjects(source: string) {
  const a = new A();
  const b = new A();
  a.setValue(source);
  return b.readValue();
}

function sameObject(source: string) {
  const a = new A();
  a.setValue(source);
  return a.readValue();
}
