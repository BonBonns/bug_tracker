"use strict";
// Mirrors the real multi-spec-parser@0.4.2 dist/src/spec-validation.js:57 isHtml() shape:
// a genuinely dangerous-shaped alternation regex ('+' immediately followed by more branch
// content) reached by a real .test() sink call.
function isHtml(contentType, head) {
  return Boolean(contentType && /text\/html/i.test(contentType)) ||
         /<!doctype\s+html|<html[\s>]/i.test(head);
}

module.exports = { isHtml };
