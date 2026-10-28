const { exec, execSync } = require("node:child_process");
function a(cmd) { exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
function b(cmd) { execSync(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
function c(dir) { exec(`ls ${dir}`); } // FIRE: mcp-js-shell-exec-template-literal
module.exports = { a, b, c };
