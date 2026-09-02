// Control 6: a NEGATIVE control -- an unrelated object literally named `fs` (and with a
// same-named `readFile` method) must NOT be treated as the real Node `fs` module.
const fs = { readFile: (p, cb) => myCustomThing(p, cb) };
Meteor.methods({
  notARealSink(userPath) {
    fs.readFile(userPath, () => {});
  }
});
function myCustomThing(p, cb) {}
