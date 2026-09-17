# Ruleset changelog

Versioned in lockstep with the scoring methodology (`04` §4.3). The first
`## <version>` heading in this file is what `semgrep_check.ruleset_version()`
records on every scan, so the newest release goes at the top.

`04` §4.3 on what a version change costs: a patch bump (rule fixes, new rules)
re-scans affected servers on the next daily crawl; a minor bump (a new rule
category) re-scans everything.

## 0.1.0 — 2026-09-17

First shipped ruleset. 32 rules across python, javascript/typescript and go,
replacing four empty `.gitkeep` files.

**Coverage.** Per language: shell execution, SSRF, unsafe deserialization and
dynamic code execution, path traversal, plus SQL injection (python),
prototype pollution (javascript), and an `mcp-specific.yaml` in each carrying
the rules that key on an MCP tool handler rather than on a generic sink.

**Every rule is positive-controlled.** `tests/test_ruleset.py` runs the whole
ruleset over `tests/fixtures/semgrep/vulnerable` and requires all 32 to fire,
then over `tests/fixtures/semgrep/safe` and requires zero findings. A rule that
cannot be made to fire does not ship — which is not hypothetical:
`mcp-js-prototype-pollution-assignment` was written with a `pattern-not` whose
metavariable matched its own positive pattern, so it was **dead on arrival** and
looked fine. It is gone, replaced by two narrower rules that each fire.

**No rule claims `high` confidence.** `03` §3 defines that tier as a measured
false-positive rate on a gold set that does not exist yet. See
`_meta/severity-mapping.yaml` and `weights.ruleset_calibrated()`.

**Known gaps, recorded rather than implied.**

- No taint analysis, per `03` §3's explicit v0.1 decision. Rules match shapes,
  not flows, so "a tool argument reaches a sink" is approximated by "a sink
  appears inside a tool handler".
- Rust, Ruby, Java and C# are inventoried by `inventory.py` and have no rules.
  A server written in them returns `UNAVAILABLE` for Code Safety, not 100.
- The false-positive rates `04` §4.2 requires per rule are unmeasured; the
  safe-fixture control is a floor, not a corpus.
