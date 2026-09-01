// Import recognition: ESM shapes -- default import, namespace import, aliased named import, and
// a node: specifier named import, each used as a real filesystem sink on a Meteor-ingress source.
import fs from 'fs';
import * as fsNs from 'fs';
import { readFile as readFileAliased } from 'fs';
import { readFile as readFileNode } from 'node:fs';

Meteor.methods({
  esmDefault(userPath) {
    fs.readFile(userPath, () => {});
  },
  esmNamespace(userPath) {
    fsNs.readFile(userPath, () => {});
  },
  esmAliasedNamed(userPath) {
    readFileAliased(userPath, () => {});
  },
  esmNodeSpecifier(userPath) {
    readFileNode(userPath, () => {});
  }
});
