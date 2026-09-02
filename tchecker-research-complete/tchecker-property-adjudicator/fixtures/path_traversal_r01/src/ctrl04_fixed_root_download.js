// Control 4: same as control 3, for res.download -- the currently-unmodeled (in the audited
// producer) sink. res.download's own `options` pass straight through to the same Express
// sendFile() internal, so a fixed root must be recognized identically to res.sendFile's.
function fixedRootDownload(req, res) {
  res.download(req.params.name, { root: '/safe/base' });
}
