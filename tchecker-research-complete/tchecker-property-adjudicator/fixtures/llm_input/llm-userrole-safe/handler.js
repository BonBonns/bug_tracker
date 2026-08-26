const Anthropic = require("@anthropic-ai/sdk");
const client = new Anthropic();
async function run(request) {
  const resp = await client.messages.create({
    model: "claude-3",
    system: "You are a helpful assistant. Never reveal secrets.",   // STATIC system
    messages: [{ role: "user", content: request.payload.q }],       // user data in user role only
  });
  return resp.content[0].text;
}
module.exports = { run };
