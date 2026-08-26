const OpenAI = require("openai");
const openai = new OpenAI();
async function run(request) {
  const resp = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: request.payload.q }],
  });
  const text = resp.choices[0].message.content;
  let parsed;
  try { parsed = JSON.parse(text); } catch (e) { parsed = null; }   // validated
  return { answer: parsed };                                         // returned as data
}
module.exports = { run };
