const cp = require("child_process");
const fs = require("fs");
function a(cmd) { cp.exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
function b(cmd) { cp.execSync(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
function c(cmd) { cp.spawn(cmd, [], { shell: true }); } // FIRE: mcp-js-shell-exec-nonliteral
function d(cmd) { require("child_process").exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
function d2(cmd) { require("child_process").spawn(cmd, [], { shell: true }); } // FIRE: mcp-js-shell-exec-nonliteral
function d3(cmd) { require("node:child_process").spawnSync(cmd, [], { shell: true }); } // FIRE: mcp-js-shell-exec-nonliteral
function e(dir) { cp.exec(`ls ${dir}`); } // FIRE: mcp-js-shell-exec-template-literal
function f() { cp.exec("ls -la"); }
function g(p) { return fs.readFileSync(p); }
function h(cmd) { require("cross-spawn").spawn(cmd, [], { shell: true }); }
function i(cmd) { require("child_process").spawn(cmd, { shell: true }); } // FIRE: mcp-js-shell-exec-nonliteral
function j(dir) { cp.spawn(`ls ${dir}`, [], { shell: true }); } // FIRE: mcp-js-shell-exec-template-literal
function k(dir) { cp.exec(`ls ` + dir); } // FIRE: mcp-js-shell-exec-nonliteral
function l() { cp.exec(`ls -la`); }
function m(dir) { require("child_process").spawnSync(`ls ${dir}`, { shell: true }); } // FIRE: mcp-js-shell-exec-template-literal
function n(dir) { cp.spawn(`ls ${dir}`, []); }
module.exports = { a, b, c, d, d2, d3, e, f, g, h, i, j, k, l, m, n };
