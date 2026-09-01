// Control 2: a user-controlled Express `root` option. The root option itself traces back to a
// source (req.body.root) -- must NOT be treated as contained just because a `root` key exists;
// root ITSELF is the real attacker-controlled operand here.
Meteor.methods({});
function userControlledRoot(req, res) {
  res.sendFile(req.params.name, { root: req.body.root });
}
