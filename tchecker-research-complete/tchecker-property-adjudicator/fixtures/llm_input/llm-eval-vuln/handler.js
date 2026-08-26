const OpenAI = require("openai");
const openai = new OpenAI();
async function run(request) {
  const resp = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: "write code for: " + request.payload.task }],
  });
  const code = resp.choices[0].message.content;   // LLM output
  return eval(code);                               // SINK: eval of model output
}
module.exports = { run };
