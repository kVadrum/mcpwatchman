# Ruleset changelog

Versioned in lockstep with the scoring methodology (`04` §4.3). The first
`## <version>` heading in this file is what `semgrep_check.ruleset_version()`
records on every scan, so the newest release goes at the top.

`04` §4.3 on what a version change costs: a patch bump (rule fixes, new rules)
re-scans affected servers on the next daily crawl; a minor bump (a new rule
category) re-scans everything.

## 0.1.1 — 2026-09-29

**The three JavaScript shell rules now require the receiver to be `child_process`.**
`mcp-js-shell-exec-nonliteral`, `mcp-js-shell-exec-template-literal` and `mcp-js-tool-arg-to-shell` matched `$CP.exec(...)` with `$CP` unconstrained, so `re.exec(line)` — the ordinary `RegExp` method — was published as a critical-severity "a shell is spawned" finding.
Found by the gold-set audits; measured on the 2026-09-29 regeneration: 273 of the 456 shown findings of `mcp-js-shell-exec-nonliteral` had a RegExp-looking receiver, across 52 servers (a lower bound — the heuristic only recognised pattern-like names).
`db.exec(sql)` and a local function named `exec` matched too.

Two halves, because neither alone reaches every binding form: semgrep's import resolution (`child_process.exec(...)`) follows a require-bound name and a named import, alias included; explicit `pattern-inside` branches catch destructured requires, namespace and default imports, and an inline `require`, each constrained to `^(node:)?child_process$`.
`tests/fixtures/semgrep/receivers/` pins both directions with `// FIRE:` markers, and the old rules produce 9 findings on its look-alikes.
The first cut dropped inline `require("child_process").spawn(…, {shell: true})` (and `spawnSync`), which the free `$CP` had matched — caught by the Codex leg before release and restored; `main`'s published data held no such finding, so nothing published under the first cut changes.
It also dropped every dynamic `import()` of `child_process` — awaited and bound (`const cp = await import(…)`), destructured, used inline, or bound in a `.then` callback — in all three rules; caught by the next `/qaa`'s review and restored before release.
`dev`'s data rows stamped 0.1.1 were scanned under the first cut: none of the 490 shell findings shown across `main`'s and `dev`'s data carries a dynamic `child_process` import in its excerpt, but evidence is capped and excerpts are five lines, so that bounds the effect rather than excluding it — the regeneration after this release is what brings those rows to the final 0.1.1.

**The JS and Python SSRF rules now require a request method.**
`axios.$M(...)`, `requests.$M(...)`, `httpx.$M(...)` and the aiohttp session method matched any attribute, so `axios.create(config)`, `axios.isAxiosError(err)` and `httpx.BasicAuth(user, pw)` were published as "an outbound request is made to a URL that is not a literal".
`$M` is now pinned to request verbs; the Go rule already named its methods and is unchanged.
The unfixed rules produce 5 findings on the SSRF look-alikes in `receivers/`.

A patch bump: rule fixes, so affected servers are re-scanned on the next run.

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
