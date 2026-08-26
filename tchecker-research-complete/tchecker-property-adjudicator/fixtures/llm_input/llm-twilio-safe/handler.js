// Twilio SMS — messages.create collides lexically with Anthropic but is NOT an
// LLM call. Must NOT be detected as an LLM site (no anthropic import, no model).
const { Twilio } = require("twilio");
const client = new Twilio("sid", "token");
async function run(request) {
  const msg = await client.messages.create({
    body: "Your code: " + request.payload.code,
    to: request.payload.phone,
    from: "+15550000000",
  });
  return eval(msg.sid);   // eval present, but msg is NOT llm output -> must not flag
}
module.exports = { run };
