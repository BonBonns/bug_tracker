// C3: different occurrences (in different functions) reach DIFFERENT sinks.
function handlerA(req, res) {
  const a = req.body;
  JSON.stringify(a);
}
function handlerB(req, res) {
  const b = req.body;
  JSON.stringify(b);
}
