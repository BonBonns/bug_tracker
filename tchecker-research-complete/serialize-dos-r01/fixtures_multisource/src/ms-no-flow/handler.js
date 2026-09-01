// C5: req.body is present in the file but never reaches the sink -- no candidate.
function handler(req, res) {
  console.log(req.body);
  const out = JSON.stringify({ ok: true });
  res.end(out);
}
