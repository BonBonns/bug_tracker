class A {
  process(x) { return x; }
}
class B {
  process(x) { return "CONST"; }
}
function exact(input) {
  return new A().process(input);
}
function exactVar(input) {
  const a = new A();
  return a.process(input);
}
function ambiguous(obj, input) {
  return obj.process(input);
}
function unknown(obj, input) {
  return obj.missing(input);
}
