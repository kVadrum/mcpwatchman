# auditmcp semgrep rules

The custom MCP-specific semgrep ruleset — the differentiating asset of auditmcp.
Published openly under [MIT](../LICENSE).

Organized by language and category:

```
rules/
├── python/         # shell-exec, ssrf, deserialization, path-traversal, mcp-specific
├── javascript/     # + prototype-pollution
├── go/
└── _meta/          # severity-mapping (rule_id -> severity, confidence), changelog
```

Each rule is tagged with a severity (`critical`/`high`/`medium`/`low`/`informational`)
and a confidence (`high`/`medium`/`low`). `_meta/severity-mapping.yaml` is the
canonical map consumed by the scoring engine.

Every rule ships with fixture tests (true positive, true negative, and a
false-positive-resistance case) and a documented false-positive rate measured
against the calibration gold set. Rules above a 20% false-positive rate are
demoted from high to medium confidence (smaller scoring deduction).
