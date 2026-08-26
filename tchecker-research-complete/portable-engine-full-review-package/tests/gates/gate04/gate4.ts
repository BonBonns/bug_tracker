class A {
  process(x: string) { return x; }
}
class B {
  process(x: string) { return "CONST"; }
}

// Same syntax as the JS ambiguous case: no receiver type.
function untyped(obj, input: string) {
  return obj.process(input);
}

// TypeScript narrows the receiver to one implementation.
function typed(obj: A, input: string) {
  return obj.process(input);
}

// A union remains genuinely ambiguous.
function unionTyped(obj: A | B, input: string) {
  return obj.process(input);
}

// Known receiver type, nonexistent method.
function missing(obj: A, input: string) {
  return obj.missing(input);
}
