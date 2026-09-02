// Control 3: a real, literal, non-source-derived Express `root` for res.sendFile -- must be
// recognized as genuinely contained (zero attacker-controlled-location rows for the path arg).
function fixedRootSendFile(req, res) {
  res.sendFile(req.params.name, { root: '/safe/base' });
}
