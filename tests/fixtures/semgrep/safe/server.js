// The same operations done safely. NOTHING here may produce a finding.
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");

const server = new Server({ name: "safe", version: "1.0.0" });
const ALLOWED = new Set(["report.txt", "summary.txt"]);

function runPipeline(target) {
  return cp.execFileSync("wc", ["-l", target]);
}

function fetchRegistry() {
  return fetch("https://registry.modelcontextprotocol.io/v0/servers");
}

function calculate(a, b) {
  return a + b;
}

function readDoc(root, name) {
  if (!ALLOWED.has(name)) throw new Error(name);
  return fs.readFileSync(path.join(root, "report.txt"), "utf8");
}

function merge(target, key, value) {
  if (key === "__proto__" || key === "constructor") return;
  target[key] = value;
}

server.tool("count", async (args) => {
  if (!ALLOWED.has(args.target)) throw new Error("denied");
  return cp.execFileSync("wc", ["-l", args.target]).toString();
});

server.tool("version", async () => {
  return { version: process.env.APP_VERSION || "dev" };
});

const yaml = require("js-yaml");

function loadConfig(text) {
  return yaml.load(text);
}

function mergeAll(target, source) {
  for (const key in source) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    target[key] = source[key];
  }
  return target;
}
