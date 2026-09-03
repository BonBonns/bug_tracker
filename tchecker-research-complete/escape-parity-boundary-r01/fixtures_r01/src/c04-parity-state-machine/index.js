// CONTROL 4: a parity-aware state-machine parser -- an escape flag toggled per
// character, so a run of escapes flips it back and forth. Expect: negative.
function splitQuoted(s) {
  const out = [];
  let escaped = false, inStr = false, buf = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (escaped) { escaped = !escaped; buf += ch; continue; }
    if (ch === '\\') { escaped = !escaped; buf += ch; continue; }
    if (ch === "'") {
      if (inStr) { out.push(buf); buf = ''; inStr = false; } else { inStr = true; }
      continue;
    }
    if (inStr) buf += ch;
  }
  return out;
}
module.exports = { splitQuoted };
