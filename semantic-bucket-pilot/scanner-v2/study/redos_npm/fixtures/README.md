# ReDoS npm-library fixtures (NPM-INTEG-R01)

Frozen raw output of `export_redos_npm_integ.sc` (Joern v4.0.608, pinned by
`tchecker-research-complete/bootstrap.sh`) run over `src/`'s own 10 synthetic files, checked in
so `check_redos_verdict.py` reproduces without needing Joern again -- same convention as
`study/lockcap/`.

`src/` covers every shape `redos_verdict.py`'s own design doc requires real, direct evidence for
(never guessed at):

| File | Shape | Expected |
|---|---|---|
| `commonjs_direct.js` | `module.exports = function(...) {...}` | resolved, DANGEROUS regex reachable |
| `commonjs_named.js` | `module.exports.foo = foo;` (named decl) + `exports.foo = function(...) {}` (inline) | both resolved, DANGEROUS reachable |
| `esm_named.mjs` | `export function foo(...) {}` + `export const foo = (...) => ...` | both resolved (js2cpg desugars to the CommonJS shape) |
| `esm_default.mjs` | `export default function foo(...) {}` | resolved via `exports["default"]` (literal-key indexAccess) |
| `class_export.js` | `module.exports = SomeClass;` | **ABSTAINED** -- resolves to the class's own `<init>`, not its real public methods |
| `dynamic_export.js` | `module.exports[key] = fn;` (non-literal key) | **ABSTAINED** -- computed/dynamic export key |
| `reexport.js` | `module.exports = require(...)` | **ABSTAINED** -- identifier resolves to a CALL, not a MethodRef |
| `safe_export.js` | exported function, fully-anchored allowlist regex | resolved export, but sink is SAFE (not DANGEROUS) -- never emitted |
| `noreach_export.js` | exported function whose own param never reaches the file's OTHER (unexported-reachable) dangerous regex | resolved export, zero reachability rows |
| `meteor_ingress_only.js` | `Meteor.methods({...})`-registered handler, NEVER exported | APPLICATION_INGRESS reachable, PACKAGE_API_INPUT **not** -- must never promote to a finding |

Real result: 11 dangerous-pattern-eligible sinks total across `src/`, 10 classified DANGEROUS
(`safe_export.js`'s own sink is the 1 SAFE exclusion); 7 rows emitted to `raw/source_facts.tsv`
(6 `PACKAGE_API_INPUT`, 1 `APPLICATION_INGRESS`) -- exactly the 6 genuinely-resolved,
genuinely-reachable exports, plus the 1 Meteor-only ingress row, with every abstained/safe/
unreached case correctly contributing zero rows.

Regenerating (only needed if a fixture file changes):
```
export JOERN_HOME=/path/to/joern-cli   # pinned version: see bootstrap.sh
"$JOERN_HOME/jssrc2cpg.sh" -o /tmp/x.cpg.bin src/
"$JOERN_HOME/joern" --script ../../../../tchecker-research-complete/tchecker-property-adjudicator/producers/export_redos_npm_integ.sc \
    --param cpgFile=/tmp/x.cpg.bin --param rawDir=raw --param srcLabel=fixture
```
