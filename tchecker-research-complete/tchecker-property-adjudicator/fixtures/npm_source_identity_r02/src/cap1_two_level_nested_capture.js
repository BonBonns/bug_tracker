// Capability 1 (closure capture identity, generalized): a value captured through TWO levels of
// function nesting (module scope -> outer -> inner), modeled on the real 2-level closureBindingId
// chain confirmed empirically against motifer-26.1.1's own ExpressLoggerFactory (module-scope
// `logger` read inside an arrow function passed to `express.use(...)`). A resolver that only
// follows ONE closureBindingId hop (rather than recursing until closureBindingId is None) would
// stop at the intermediate proxy Local instead of the true module-scope origin.
let counter = 0;

function bump() {
  counter = counter + 1;
}

function makeOuter() {
  return function outer() {
    return function inner() {
      // two nesting levels away from the module-scope `counter` declaration
      return counter;
    };
  };
}

module.exports = { bump, makeOuter };
