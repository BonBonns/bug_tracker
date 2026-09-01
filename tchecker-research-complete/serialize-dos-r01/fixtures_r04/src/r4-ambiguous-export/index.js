// C7: ambiguous call edge -- ident assigned from two different MethodRefs -- abstain.
function A(x) {
  return JSON.stringify(x);
}
function B(x) {
  return JSON.stringify(x);
}
let Exported = A;
Exported = B;
module.exports = Exported;
