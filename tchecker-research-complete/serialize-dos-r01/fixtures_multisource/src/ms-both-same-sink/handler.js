// C2: both occurrences reach the SAME sink -- should be one deduplicated finding
// (one evidence_final.json for that one sink), not two.
function handler(req, res, useA) {
  const payload = useA ? req.body : req.body;
  const out = JSON.stringify(payload);
  res.end(out);
}
