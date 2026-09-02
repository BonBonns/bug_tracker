// Import recognition: destructured CommonJS require -- `const { readFile } = require('fs')`. The
// resulting bare `readFile(...)` call has NO `fs.` receiver at all -- the audited producer's
// `code.startsWith("fs.")` check structurally cannot catch this shape.
const { readFile } = require('fs');
Meteor.methods({
  destructuredRead(userPath) {
    readFile(userPath, () => {});
  }
});
