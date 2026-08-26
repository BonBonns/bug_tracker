#!/usr/bin/env node
// TSC UNION SIDECAR: extracts declared UNION member types per function parameter
// using the REAL TypeScript checker — the information jssrc2cpg destroys (measured:
// param=ANY, arg=A:<init>, candidates=A-only, dynamicTypeHints=A-only).
// Output (tsv): functionName \t paramName \t memberA|memberB|... (declared order)
// This is frontend-side interpretation; the neutral core never sees it.
const ts = require('/home/claude/js-frontend/node_modules/typescript/lib/typescript.js');
const fs = require('fs');
const path = require('path');

const srcDir = process.argv[2];
const outFile = process.argv[3];
const files = fs.readdirSync(srcDir).filter(f => f.endsWith('.ts')).map(f => path.join(srcDir, f));
const program = ts.createProgram(files, { strict: false });
const checker = program.getTypeChecker();
const rows = [];

for (const sf of program.getSourceFiles()) {
  if (!files.includes(sf.fileName)) continue;
  const visit = (node) => {
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name && node.parameters) {
      const fname = node.name.getText(sf);
      for (const p of node.parameters) {
        if (p.type && ts.isUnionTypeNode(p.type)) {
          const members = p.type.types.map(t => t.getText(sf));
          rows.push([fname, p.name.getText(sf), members.join('|')].join('\t'));
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}
fs.writeFileSync(outFile, rows.join('\n') + (rows.length ? '\n' : ''));
console.log(`UNION_SIDECAR rows=${rows.length}`);
