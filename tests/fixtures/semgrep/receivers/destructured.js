const { exec, execSync } = require("node:child_process");
function a(cmd) { exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
function b(cmd) { execSync(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
module.exports = { a, b };
