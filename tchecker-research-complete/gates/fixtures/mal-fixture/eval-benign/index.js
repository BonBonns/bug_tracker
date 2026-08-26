module.exports = function decode(b64) {
  const buf = Buffer.from(b64, "base64");    // decoded, but used as data
  return buf.length;                          // never eval'd
};
