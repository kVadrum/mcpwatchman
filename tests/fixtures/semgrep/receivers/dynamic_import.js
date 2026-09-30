async function a(cmd) { const cp = await import("node:child_process"); cp.exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
async function b(cmd) { const { exec } = await import("child_process"); exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
async function c(cmd) { (await import("child_process")).exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
async function d(cmd) { const cp = await import("child_process"); cp.spawn(cmd, [], { shell: true }); } // FIRE: mcp-js-shell-exec-nonliteral
async function e(dir) { const cp = await import("child_process"); cp.exec(`ls ${dir}`); } // FIRE: mcp-js-shell-exec-nonliteral, mcp-js-shell-exec-template-literal
function f(cmd) { import("child_process").then((cp) => cp.exec(cmd)); } // FIRE: mcp-js-shell-exec-nonliteral
function g(cmd) { import("child_process").then(function (cp) { cp.execSync(cmd); }); } // FIRE: mcp-js-shell-exec-nonliteral
function h(cmd) { import("child_process").then(({ exec }) => exec(cmd)); } // FIRE: mcp-js-shell-exec-nonliteral
async function i(cmd) { (await import("child_process")).spawnSync(cmd, { shell: true }); } // FIRE: mcp-js-shell-exec-nonliteral
async function x1(s) { return (await import("./regex.js")).exec(s); }
function x2(sql) { import("./db.js").then((db) => db.exec(sql)); }
function x3(s) { import("child_process").then(() => { const re = /a/; re.exec(s); }); }
async function x4(cmd) { const cs = await import("cross-spawn"); cs.spawn(cmd, [], { shell: true }); }
async function x5() { const cp = await import("child_process"); cp.exec("ls -la"); }
module.exports = { a, b, c, d, e, f, g, h, i, x1, x2, x3, x4, x5 };
