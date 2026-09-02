// Control 10: the res.sendFile options object is not a statically-resolvable literal (a plain
// variable) -- must abstain, never guess whether a 'root' key is present.
function unresolvedOptions(req, res, opts) {
  res.sendFile(req.params.name, opts);
}
