// D6: the shape found in a real CSV parser -- the quote position comes from a
// search rather than a comparison, and both delimiters are configurable. Both
// facts block a verdict, and the site must abstain rather than vanish.
function parse(input, config) {
  let quoteChar = '"';
  if (config && config.quoteChar) quoteChar = config.quoteChar;
  let escapeChar = quoteChar;
  if (config && config.escapeChar !== undefined) escapeChar = config.escapeChar;

  const rows = [];
  let cursor = 0;
  let quoteSearch = input.indexOf(quoteChar, cursor);
  while (quoteSearch !== -1) {
    if (quoteChar !== escapeChar && quoteSearch !== 0 && input[quoteSearch - 1] === escapeChar) {
      quoteSearch = input.indexOf(quoteChar, quoteSearch + 1);
      continue;
    }
    rows.push(input.slice(cursor, quoteSearch));
    cursor = quoteSearch + 1;
    quoteSearch = input.indexOf(quoteChar, cursor);
  }
  return rows;
}
module.exports = { parse };
