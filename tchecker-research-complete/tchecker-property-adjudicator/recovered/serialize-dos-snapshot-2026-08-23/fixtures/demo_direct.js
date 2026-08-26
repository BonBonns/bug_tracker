// ESTABLISHED: attacker body serialized directly, no transform
function handler(req, res) {
  const body = JSON.stringify(req.body);
  res.end(body);
}
