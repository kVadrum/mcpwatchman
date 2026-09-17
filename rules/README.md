# mcpwatchman semgrep rules

The custom MCP-specific semgrep ruleset — the differentiating asset of mcpwatchman.
Published openly under [MIT](../LICENSE), because a scoring rule you cannot read
is a mystery number with extra steps.

```
rules/
├── python/         # shell-exec, ssrf, deserialization, path-traversal,
│                   # sql-injection, mcp-specific
├── javascript/     # the same, plus prototype-pollution, minus sql-injection
├── go/             # the same, minus sql-injection and prototype-pollution
└── _meta/          # severity-mapping.yaml (canonical), changelog.md (version)
```

## What makes a rule "MCP-specific"

Each language's `mcp-specific.yaml` keys on the shape of an **MCP tool handler**
rather than on a generic sink. The distinction is not cosmetic. A tool argument
is not user input in the usual sense of a person typing into a form — it is a
value a language model was persuaded to produce, and the persuasion can arrive
from a web page, an email, or a document the model was asked to summarise. So
"the caller is trusted" is not a mitigation: the caller is a model that read
something attacker-controlled two steps ago.

> The scoring methodology is published at <https://mcpwatchman.com>. The
> numbered design documents cited as `03` / `04` are internal and are not
> part of this repository; section numbers are given so the published
> methodology can be followed.

## Severity and confidence

`_meta/severity-mapping.yaml` is the **canonical** map from rule id to
(severity, confidence), and the scoring engine reads only that. The `severity:`
field inside each rule file is semgrep's own schema-required field in semgrep's
vocabulary (`ERROR`/`WARNING`/`INFO`); it is *derived* from the canonical
severity and asserted in `tests/test_ruleset.py`, so the two cannot drift into
disagreeing about how bad a finding is.

**No rule currently claims `high` confidence, and that is a statement about our
evidence rather than about the rules.** The methodology
(§3) defines the confidence tiers by
measurement — high is a verified <5% false-positive rate on the calibration gold
set, medium is <20%. That gold set has not been built yet. Claiming `high`
would assert a measurement nobody has performed. Until calibration runs, the
ceiling is `medium`, enforced in code by `weights.ruleset_calibrated()`.

This costs points in the safe direction: a critical/high finding deducts 30
where a critical/medium deducts 20, so every server presently scores **better**
than it eventually will.

## How the rules are tested

`tests/test_ruleset.py` runs the entire ruleset over two fixture trees:

- `tests/fixtures/semgrep/vulnerable/` — **every declared rule must fire.** A
  rule that cannot be made to fire does not ship. This is not hypothetical: the
  first draft of the prototype-pollution rule carried a `pattern-not` whose
  metavariable matched its own positive pattern, so it was dead on arrival while
  looking perfectly healthy. Valid YAML, clean `semgrep --validate`, zero
  matches, forever.
- `tests/fixtures/semgrep/safe/` — **no rule may fire.** The same operations
  written safely. For this product a false accusation is the expensive failure.

That is a floor, not a corpus. It proves each rule is alive and not trivially
wrong; it does not measure a false-positive rate, and nothing here claims to.

## Known gaps

Recorded here rather than left for a reader to discover:

- **No taint analysis** — The scoring methodology §3 makes this an
  explicit v0.1 decision. Rules match shapes, not flows, so "a tool argument
  reaches a sink" is approximated by "a sink appears inside a tool handler".
- **Four inventoried languages have no rules** — Rust, Ruby, Java and C#. A
  server written in one of them reports Code Safety as *not assessed*, with the
  reason, and never as 100.
- **No per-rule false-positive rates.** They arrive with the gold set.

See `_meta/changelog.md` for the ruleset version and what each release changed.
