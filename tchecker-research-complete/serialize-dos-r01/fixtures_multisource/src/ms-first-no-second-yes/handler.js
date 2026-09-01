// C1: first occurrence does not flow (ternary condition), second does (the argument).
// The exact minimal reproduction of the real motifer@26.1.1 shape.
function handler(req, res) {
  const x = req.body ? JSON.stringify(req.body) : null;
  res.end(x);
}
