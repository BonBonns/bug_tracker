// SSRF sink-semantics characterization fixtures. Each function isolates ONE call shape. No
// property-propagation logic is exercised here -- this file exists purely to let the
// characterization script identify, for each call site, which exact operand is host-bearing.
const axios = require('axios');
const http = require('http');
const https = require('https');
const got = require('got');
const request = require('request');
const fetch = require('node-fetch');

// --- fetch(url) family ---
function fetch_full_url(userUrl) {
  return fetch(userUrl);
}
function fetch_url_object(userUrl) {
  return fetch(new URL(userUrl));
}
function nodefetch_full_url(userUrl) {
  return fetch(userUrl);
}

// --- axios(...) family ---
function axios_direct(userUrl) {
  return axios(userUrl);
}
function axios_get_method(userUrl) {
  return axios.get(userUrl);
}
function axios_post_method(userUrl) {
  return axios.post(userUrl, {});
}
function axios_config_url_only(userUrl) {
  return axios({ url: userUrl });
}
function axios_config_fixed_baseurl_attacker_path(attackerPath) {
  // host is FIXED (baseURL); attackerPath must NOT be treated as host control
  return axios({ baseURL: 'https://fixed.example', url: attackerPath });
}
function axios_config_baseurl_only_attacker(userBaseUrl) {
  // here the attacker DOES control the host, via baseURL specifically
  return axios({ baseURL: userBaseUrl, url: '/fixed/path' });
}

// --- http.request / https.request family ---
function http_request_string(userUrl) {
  return http.request(userUrl);
}
function http_request_url_object(userUrl) {
  return http.request(new URL(userUrl));
}
function http_request_options_hostname(userHost) {
  return http.request({ hostname: userHost, path: '/fixed' });
}
function http_request_options_host(userHost) {
  return http.request({ host: userHost, path: '/fixed' });
}
function http_request_options_path_only(attackerPath) {
  // host is NOT specified here (defaults to localhost); path is attacker-controlled but that is
  // NOT host control -- must not be flagged as a host-bearing operand
  return http.request({ path: attackerPath });
}
function https_request_options_hostname(userHost) {
  return https.request({ hostname: userHost, path: '/fixed' });
}

// --- got(...) family ---
function got_full_url(userUrl) {
  return got(userUrl);
}
function got_options_url(userUrl) {
  return got({ url: userUrl });
}

// --- request(...) legacy library family ---
function request_full_url(userUrl) {
  return request(userUrl, () => {});
}
function request_options_url(userUrl) {
  return request({ url: userUrl }, () => {});
}
function request_options_uri(userUrl) {
  return request({ uri: userUrl }, () => {});
}

// --- unresolved wrapper: must ABSTAIN (UNSUPPORTED), not guess ---
function callsUnresolvedWrapper(userUrl) {
  return someExternalHttpLibrary.doRequest(userUrl);
}
function callsLocalWrapperNotDefinedHere(userUrl) {
  return notDefinedInThisFile(userUrl);
}
