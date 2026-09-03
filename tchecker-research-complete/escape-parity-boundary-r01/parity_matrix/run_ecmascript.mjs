// ECMAScript engine harness. Applies each ECMAScript pattern to each subject using the
// JavaScript engine's own RegExp. Parser behaviour only.
import { readFileSync } from 'node:fs';
const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
for (const c of cases) {
  if (c.dialect !== 'ECMASCRIPT') continue;
  const row = { rule_id: c.rule_id, dialect: 'ECMASCRIPT', engine: 'node-regexp',
                run_length: c.run_length, parity: c.parity };
  let re;
  try { re = new RegExp(c.pattern, 'gs'); }
  catch (e) { row.engine_error = true; row.detail = String(e.message).slice(0, 120);
              console.log(JSON.stringify(row)); continue; }
  const vals = [];
  for (const m of c.subject.matchAll(re)) vals.push(m[1] !== undefined ? m[1] : m[0]);
  row.recovered = vals;
  row.matches_parity_rule = JSON.stringify(vals) === JSON.stringify(c.expected);
  console.log(JSON.stringify(row));
}
