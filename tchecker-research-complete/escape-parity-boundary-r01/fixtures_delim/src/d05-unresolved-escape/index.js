// D5: the quote is a literal but the ESCAPE character is configurable. The
// escape half of the rule is what decides parity, so an unresolved escape is
// just as blocking as an unresolved quote.
function splitQuoted(s, cfg) {
  let escapeChar = '\\';
  if (cfg && cfg.escapeChar) escapeChar = cfg.escapeChar;
  const out = [];
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '"' && (i === 0 || s[i - 1] !== escapeChar)) {
      if (start < 0) start = i; else { out.push(s.slice(start + 1, i)); start = -1; }
    }
  }
  return out;
}
module.exports = { splitQuoted };
