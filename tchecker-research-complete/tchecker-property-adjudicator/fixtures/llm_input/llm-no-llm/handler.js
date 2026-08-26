function run(request) {
  const expr = "1 + 1";           // local, not LLM output
  return eval(expr);              // eval, but not model-fed
}
module.exports = { run };
