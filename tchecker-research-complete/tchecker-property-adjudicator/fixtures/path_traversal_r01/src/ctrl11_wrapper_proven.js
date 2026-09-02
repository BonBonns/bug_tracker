// Control 11: a containment wrapper whose OWN body performs a real canonicalize-then-
// boundary-check internally -- must be recognized as genuinely proving containment when called to
// guard a sink.
const path = require('path');
const fs = require('fs');
function isContained(candidate) {
  const resolved = path.resolve('/safe/base', candidate);
  return resolved === '/safe/base' || resolved.startsWith('/safe/base' + path.sep);
}
Meteor.methods({
  wrapperProven(userPath) {
    if (isContained(userPath)) {
      fs.readFile(userPath, () => {});
    }
  }
});
