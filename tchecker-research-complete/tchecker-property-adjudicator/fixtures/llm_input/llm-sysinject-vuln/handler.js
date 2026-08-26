const Anthropic = require("@anthropic-ai/sdk");
const client = new Anthropic();
async function run(request) {
  const resp = await client.messages.create({
    model: "claude-3",
    system: "You are an assistant. Rules: " + request.payload.rules,  // INJECTION into system
    messages: [{ role: "user", content: request.payload.q }],
  });
  return resp.content[0].text;
}
module.exports = { run };
