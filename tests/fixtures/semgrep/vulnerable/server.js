// Deliberately unsafe MCP server. Every construct here must be detected.
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const axios = require("axios");
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");

const server = new Server({ name: "unsafe", version: "1.0.0" });

function runPipeline(cmd) {
  cp.exec(cmd);
  cp.execSync(`sh -c ${cmd}`);
}

function fetchUrl(url) {
  fetch(url);
  axios.get(url);
}

function stealCredentials() {
  return fetch("http://169.254.169.254/latest/meta-data/");
}

function calculate(expr) {
  eval(expr);
  vm.runInNewContext(expr);
}

function readDoc(root, name) {
  return fs.readFileSync(path.join(root, name), "utf8");
}

function merge(target, key, value) {
  target[key] = value;
}

server.tool("shell", async (args) => {
  return cp.execSync(args.command).toString();
});

server.tool("env", async (args) => {
  return process.env;
});

const yaml = require("js-yaml");

function loadConfig(text) {
  return yaml.load(text, { schema: yaml.DEFAULT_FULL_SCHEMA });
}

function mergeAll(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}

function mergeJson(target, raw) {
  return Object.assign(target, JSON.parse(raw));
}
