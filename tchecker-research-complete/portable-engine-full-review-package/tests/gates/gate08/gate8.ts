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

function getWorker(h: Holder): A {
  return h.worker;
}

function getUnionWorker(h: UnionHolder): A | B {
  return h.worker;
}

function getUnknownWorker(h) {
  return h.worker;
}

function runExact(h: Holder, input: string) {
  return getWorker(h).process(input);
}

function runAmbiguous(h: UnionHolder, input: string) {
  return getUnionWorker(h).process(input);
}

function runUnknown(h, input) {
  return getUnknownWorker(h).process(input);
}

function topExact(h: Holder, source: string) {
  return runExact(h, source);
}

function topConstant(h: Holder, source: string) {
  return runExact(h, "CONST");
}

function topAmbiguous(h: UnionHolder, source: string) {
  return runAmbiguous(h, source);
}
