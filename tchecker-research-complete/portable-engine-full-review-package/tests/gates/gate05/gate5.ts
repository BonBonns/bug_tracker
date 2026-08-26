class A {
  process(x: string) { return x; }
}

class B {
  process(x: string) { return "CONST"; }
}

class Holder {
  worker: A;
}

class UnionHolder {
  worker: A | B;
}

function typedProperty(h: Holder, input: string) {
  return h.worker.process(input);
}

function untypedProperty(h, input) {
  return h.worker.process(input);
}

function unionProperty(h: UnionHolder, input: string) {
  return h.worker.process(input);
}

function missingMethod(h: Holder, input: string) {
  return h.worker.missing(input);
}
