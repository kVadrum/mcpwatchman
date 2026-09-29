// None of these is a shell. Each one matched before ruleset 0.1.1.
const re = /(\d+)-(\d+)/;
const pattern = new RegExp("a+");
const cp = { exec: (s: string) => s };
export function a(s: string) { return re.exec(s); }
export function b(s: string) { return /x(y)/g.exec(s); }
export function c(s: string, t: string) { return new RegExp(s).exec(t); }
export function d(s: string) { return pattern.exec(s); }
export function e(db: any, sql: string) { return db.exec(sql); }
export function f(db: any, id: string) { return db.exec(`SELECT * FROM t WHERE id = ${id}`); }
function exec(x: string) { return x; }
export function g(s: string) { return exec(s); }
export function h(s: string) { return cp.exec(s); }
