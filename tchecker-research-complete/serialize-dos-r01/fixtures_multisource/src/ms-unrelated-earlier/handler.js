// C4: an earlier, unrelated occurrence -- inside a DIFFERENT nested closure that never
// contributes to this function's own return path -- must not suppress the real, later
// flow to the sink.
function handler(req, res) {
  req.on('data', function () { console.log(req.body); });
  const payload = req.body;
  const out = JSON.stringify(payload);
  res.end(out);
}
