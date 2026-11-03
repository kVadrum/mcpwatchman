// SQL built by string (ruleset 0.1.4). FIRE lines must match; every other
// line is a look-alike that must not.
await pool.query(`SELECT * FROM users WHERE name = '${name}'`); // FIRE: mcp-js-sql-string-built
const rows = await client.query("SELECT id FROM " + table + " LIMIT 10"); // FIRE: mcp-js-sql-string-built
db.prepare(`DELETE FROM notes WHERE id = ${args.id}`).run(); // FIRE: mcp-js-sql-string-built
await conn.execute(`UPDATE accounts SET plan = '${plan}' WHERE id = 1`); // FIRE: mcp-js-sql-string-built
await sql.unsafe(`select ${cols} from ${tableName}`); // FIRE: mcp-js-sql-string-built
await knex.raw("insert into log (msg) values ('" + msg + "')"); // FIRE: mcp-js-sql-string-built
await prisma.$queryRawUnsafe(`SELECT * FROM "${schema}".items`); // FIRE: mcp-js-sql-string-built

await pool.query("SELECT * FROM users WHERE name = $1", [name]);
await pool.query(sql`SELECT * FROM users WHERE name = ${name}`);
await prisma.$queryRaw`SELECT * FROM items WHERE id = ${id}`;
db.prepare("DELETE FROM notes WHERE id = ?").run(args.id);
await client.query(userSuppliedSql);
const m = re.exec(`select a from b ${x}`.toString());
logger.info(`SELECT took ${ms}ms FROM cache`);
const label = `Select a file from ${dir}`;
await api.get(`/select/from/${id}`);
await cache.get("users:" + id);
await client.query(`SET search_path TO ${schema}`);
db.prepare("INSERT INTO t (a) VALUES (?) " + "ON CONFLICT DO NOTHING").run(a);
const TABLE = "users";
await pool.query("SELECT * FROM " + TABLE + " WHERE id = $1", [id]);
await pool.query(`SELECT * FROM ${TABLE} WHERE id = $1`, [id]);
