// CONTROL 11: a parity-correct quote parser that has an unrelated formatting problem
// (it drops the separator when re-joining). Expect: outside this property.
function reformat(s) {
  const values = [];
  let escaped = false, inStr = false, buf = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (escaped) { escaped = !escaped; buf += ch; continue; }
    if (ch === '\\') { escaped = !escaped; buf += ch; continue; }
    if (ch === "'") {
      if (inStr) { values.push(buf); buf = ''; inStr = false; } else { inStr = true; }
      continue;
    }
    if (inStr) buf += ch;
  }
  return values.join('');   // unrelated defect: separator dropped
}
module.exports = { reformat };
