const cp = require("child_process");
const re = /^[a-z]+$/;
const server = { tool() {} };
server.tool("run", {}, async (args) => {
  cp.exec(args.command); // FIRE: mcp-js-shell-exec-nonliteral, mcp-js-tool-arg-to-shell
});
server.tool("check", {}, async (args) => {
  return re.exec(args.name);
});
server.tool("later", {}, async (args) => {
  const later = await import("node:child_process");
  later.execSync(args.command); // FIRE: mcp-js-shell-exec-nonliteral, mcp-js-tool-arg-to-shell
});
