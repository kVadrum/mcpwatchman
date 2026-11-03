package fixtures

const recallTable = "recall_misses"

// SQL built by string (ruleset 0.1.4). FIRE lines must match; every other
// line is a look-alike that must not.

func handlers() {
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)) // FIRE: mcp-go-sql-string-built
	_, _ = db.Exec("DELETE FROM notes WHERE id = " + id) // FIRE: mcp-go-sql-string-built
	row := tx.QueryRowContext(ctx, fmt.Sprintf("select id from %s limit 1", table)) // FIRE: mcp-go-sql-string-built
	_, _ = conn.ExecContext(ctx, "UPDATE accounts SET plan = '"+plan+"' WHERE id = 1") // FIRE: mcp-go-sql-string-built

	rows2, _ := db.Query("SELECT * FROM users WHERE name = $1", name)
	_, _ = db.Exec("DELETE FROM notes WHERE id = ?", id)
	msg := fmt.Sprintf("select a file from %s", dir)
	_ = log.Exec(fmt.Sprintf("ran %s", name))
	_, _ = db.Query(query)
	_, _ = db.Exec("DELETE FROM " + recallTable + " WHERE id = ?", id)
	_, _ = db.Exec("DELETE FROM notes " + "WHERE id = ?", id)
	_ = rows; _ = row; _ = rows2; _ = msg
}
