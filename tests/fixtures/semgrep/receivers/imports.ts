import { exec } from "child_process";
import * as cp from "node:child_process";
import cpd from "child_process";
import { execSync as run } from "child_process";
export function a(cmd: string) { exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
export function b(cmd: string) { cp.execSync(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
export function c(cmd: string) { cpd.exec(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
export function d(cmd: string) { run(cmd); } // FIRE: mcp-js-shell-exec-nonliteral
