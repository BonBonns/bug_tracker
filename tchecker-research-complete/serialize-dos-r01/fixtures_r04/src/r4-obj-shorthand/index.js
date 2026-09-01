// C4: object-literal shorthand exported function.
function foo(input) {
  return JSON.stringify(input);
}
function bar() {
  return "safe";
}
module.exports = { foo, bar };
