"use strict";
function safeCheck(s) {
  return /^[a-z]+$/.test(s);
}
module.exports = { safeCheck };
