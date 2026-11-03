const axios = require("axios");
async function a(u) { return axios.get(u); } // FIRE: mcp-js-ssrf-nonliteral-url
async function b(u) { return axios.post(u, {}); } // FIRE: mcp-js-ssrf-nonliteral-url
async function c(cfg) { return axios.request(cfg); } // FIRE: mcp-js-ssrf-nonliteral-url
async function d(u) { return fetch(u); } // FIRE: mcp-js-ssrf-nonliteral-url
function e(cfg) { return axios.create(cfg); }
function f(err) { return axios.isAxiosError(err); }
function g(err) { return axios.isCancel(err); }
async function h() { return axios.get("https://example.com/"); }
module.exports = { a, b, c, d, e, f, g, h };

// The metadata endpoint, ruleset 0.1.3: a literal is listed wherever it is,
// a comment never — not even this one, which names 169.254.169.254.
const BLOCKED_HOSTS = ["169.254.169.254", "metadata.google.internal"]; // FIRE: mcp-js-ssrf-metadata-endpoint, mcp-js-ssrf-metadata-endpoint
