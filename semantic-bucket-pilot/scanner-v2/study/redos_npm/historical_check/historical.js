module.exports.cve20255892 = function checkColon(input) {
  return input.search(/^:|\s+:/);
};
module.exports.autotranslate = function checkAutotranslate(input) {
  return input.replace(/^\s*<p>|<\/p>\s*$/gm, '');
};
module.exports.corsSafe = function checkCors(input) {
  return /^(https?:\/\/)?[a-z0-9.-]+$/.test(input);
};
