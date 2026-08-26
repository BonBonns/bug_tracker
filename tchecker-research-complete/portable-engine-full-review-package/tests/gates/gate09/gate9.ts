class A {
  value: string;

  setValue(v: string) {
    this.value = v;
  }

  readValue() {
    return this.value;
  }
}

class Holder {
  worker: A;
}

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

function topConstant(h: Holder, source: string) {
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
