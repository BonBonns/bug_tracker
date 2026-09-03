// D3: the quote character is configurable, so its identity cannot be pinned
// down. The site must still be recorded -- as an abstention, never silence.
function splitQuoted(s, cfg) {
  let quoteChar = '"';
  if (cfg && typeof cfg.quoteChar === 'string') quoteChar = cfg.quoteChar;
  const ESCAPE = '\\';
  const out = [];
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === quoteChar && (i === 0 || s[i - 1] !== ESCAPE)) {
      if (start < 0) start = i; else { out.push(s.slice(start + 1, i)); start = -1; }
    }
  }
  return out;
}
module.exports = { splitQuoted };
