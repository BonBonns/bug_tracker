// Control 5: aliased fs import -- `const filesystem = require('fs')`. The audited producer's own
// literal `code.startsWith("fs.")` check misses this entirely (confirmed in
// docs/milestones/PATH_TRAVERSAL_R01_AUDIT.md item 7.1); this file's structural methodFullName
// resolution must catch it.
const filesystem = require('fs');
Meteor.methods({
  aliasedRead(userPath) {
    filesystem.readFile(userPath, () => {});
  }
});
