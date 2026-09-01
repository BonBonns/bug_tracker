// Genuinely vendored, generated build output -- NOT referenced by package.json's "main",
// "module", "types"/"typings", or any "exports" leaf. This folder must stay excluded; the
// coverage-check tool must not try to un-ignore it, because it is not any declared entrypoint's
// own path. Contains a dangerous-shaped literal on purpose, to prove it's really being skipped
// (if it were wrongly recovered, this sink would show up in a rerun of the frozen producer).
function isMarkupLike(contentType, head) {
  return Boolean(contentType && /text\/html/i.test(contentType)) ||
         /<!doctype\s+html|<html[\s>]/i.test(head);
}
module.exports = { isMarkupLike };
