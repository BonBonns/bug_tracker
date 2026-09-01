# Real historical vulnerable/fixed differential: CVE-2025-5892

Per direct instruction: "Run the complete producer -> adjudicator -> reducer chain on the actual
vulnerable and fixed versions associated with the historical ReDoS case." This is that -- the
ACTUAL file, not a synthetic wrapper around the same pattern (see `historical_check/` for the
copy-fidelity check that preceded this).

**Real target**: RocketChat/Rocket.Chat, `apps/meteor/app/irc/server/servers/RFC2813/parseMessage.js`,
`CVE-2025-5892` (RFC2813 IRC message parser, `parseMessage`), fixed in
[PR #35711](https://github.com/RocketChat/Rocket.Chat/pull/35711).

  vulnerable file: fetched at commit `72725d391e79b44e7380ee2fe640e2e4426c77ca`
                    (the real parent of the fix commit) -- `vuln/src/parseMessage.js`
  fixed file:       fetched at commit `cd5c60eeb5b68ec5a57b6a7e579def9abbfd79ab`
                    (the real fix commit) -- `fixed/src/parseMessage.js`

Real change (confirmed against the fetched files directly): `line.search(/^:|\s+:/)` (vulnerable)
-> `line.search(/^:(?<!\s)\s+:/)` (fixed, negative lookbehind added). Both files use the same
real export shape: `module.exports = function parseMessage(line) { ... }`.

`vuln/raw/` and `fixed/raw/` are `export_redos_npm_integ.sc`'s own frozen real output (Joern
v4.0.608) over each file. Regenerating: same procedure as `../fixtures/README.md`.

## Real result, complete producer -> adjudicator -> reducer chain

| | sink targets | DANGEROUS | PACKAGE_API_INPUT rows | `redos_verdict.py` findings |
|---|---|---|---|---|
| **vulnerable** | 7 | 1 (L52, `/^:\|\s+:/`) | 7 (dataflow through `line`'s own 7 real reassignment points) | **1** -- `PACKAGE_API_INPUT_REACHABLE` |
| **fixed** | 7 | **0** (neither the modified sink nor the file's other `.match()` call matches the frozen DANGEROUS shape) | 0 | **0** |

Confirms, on the real historical file (not a synthetic pattern-in-a-wrapper), exactly what was
required: the vulnerable version produces `PACKAGE_API_INPUT_REACHABLE`; the fixed version does
not.
