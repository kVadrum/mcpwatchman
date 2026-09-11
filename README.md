# mcpwatchman

**Independent security and quality audit for [Model Context Protocol](https://modelcontextprotocol.io) servers.**

`mcpwatchman` continuously scans every server in the official MCP registry and publishes a transparent, evidence-linked assessment of each one — so you can answer "is this MCP server safe to install?" before you wire it into your agent.

> **Status: early — building in public.**
> The methodology and architecture are settled and the repository is scaffolded; the scanner, scoring engine, site, and CLI are under active construction.
> **Nothing here is production-ready, and no scores have been published yet.**
> Watch the repo to follow along.

---

## Why

MCP adoption is accelerating across Claude Code, Cursor, Continue, Zed, Goose and more — and people are installing servers with the same blind trust they once gave `curl | bash`.
Research on thousands of public MCP servers has found widespread server-side request forgery, unsafe command execution, and servers exposed over HTTP with no authentication at all.

The official registry is **metadata-only by design** — it lists what exists, not what's safe.
`mcpwatchman` is the independent safety layer on top of it.
The closest analogues are [Mozilla Observatory](https://observatory.mozilla.org/) and [OpenSSF Scorecard](https://scorecard.dev/): independent, transparent, free, and trusted precisely because they aren't selling anything to the projects they score.

## How it works

A daily pass over the official registry, then per server:

1. **Resolve** the declared source repository and package artifacts from registry metadata.
2. **Fetch** published source and lockfiles — a shallow, sparse clone at a pinned commit, into a per-job sandboxed workspace with resource limits and no inbound network.
3. **Analyze statically** — an MCP-specific [semgrep](https://semgrep.dev) ruleset for the patterns that matter in this ecosystem (tool-handler shell exec, unvalidated URL fetches, unsafe deserialization, path traversal), plus dependency CVE scanning, transport and auth inspection, and repository maintenance signals.
4. **Score** each axis from the findings, with every point of the score traceable to the artifact that produced it.
5. **Publish** to the site, JSON API, RSS feeds, and CLI.

**The analysis is static, always.**
We read published source, manifests and lockfiles.
**We never execute the code we scan**, and we never connect to a running server instance.

**So here is what a good score cannot tell you.**
A server that behaves badly only when a tool is actually invoked is invisible to static analysis, and no score here should be read as a runtime guarantee.
Running every server we scan is a substantially larger sandboxing problem than reading it, and we would rather be narrow and honest about it than broad and quietly wrong.

## How it scores

Every server is rated 0–100 on five axes, and **every score links to its evidence** — a file and line, a CVE identifier, a commit date.
No mystery numbers.

| Axis | Default weight | Captures |
|---|---|---|
| **Code Safety** | 30% | Static-analysis findings: shell exec, SSRF, deserialization, path traversal |
| **Auth Posture** | 20% | Authentication model, transport security, secret handling, scope granularity |
| **Dependency Health** | 20% | Known CVEs in direct and transitive dependencies |
| **Maintenance** | 15% | Activity, release cadence, issue responsiveness, bus factor |
| **Transparency** | 15% | License validity, documented behavior, declared scopes |

**Per-axis scores ship first; the composite waits for calibration.**
The weights above are *provisional* starting values informed by the threat literature — they live in [`src/mcpwatchman/workers/scoring/weights.py`](src/mcpwatchman/workers/scoring/weights.py) and are versioned like any other code.
They become final only after calibration against a hand-audited gold set of roughly 30 servers spanning categories and a deliberate range of expected results.
Until that regression suite is green, public surfaces show the per-axis scores and suppress the composite.
A single blended number is the easiest thing to publish and the easiest thing to get quietly wrong, so it is the last thing we will ship.

The full methodology is published openly — anyone can audit our auditing.

## Principles

- **Methodology over marketing.**
  Every check, weight and threshold is documented and versioned.
- **Evidence or it doesn't ship.**
  A finding with no linked artifact doesn't appear.
- **Facts, not characterizations.**
  We describe observed code patterns, never intent.
  Maintainers can appeal any finding.
- **Collaborative, not competitive.**
  We overlay the official registry; we don't replace it.
  A server exists here only if the official registry lists it.
- **Free, and staying that way.**
  The scanner, ruleset, site, API, RSS feeds and CLI are MIT-licensed and free.

## Disclosure

Findings fall into two tracks, and they are handled differently on purpose.

**Track A — publicly observable patterns.**
Static-analysis hits, license and transport facts: anyone can run the same tools against the same published source and see the same thing.
There is no informational asymmetry to protect, so these are **not embargoed** — they appear on the server's page from the first scan that detects them.
Maintainer notification before publication is the right courtesy; delaying a fact every reader could derive themselves is not.

**Track B — findings that warrant coordination.**
Default embargo is **14 days** from maintainer contact, shortened to **7** where there is evidence of active exploitation, and extended up to **45 days total** when a maintainer comes back with a concrete fix timeline.
If we cannot reach a maintainer within 48 hours of the first attempt the clock still starts, with a longer target — being slow to check email is not the same as being unresponsive, and we don't punish it.

**Appeals.**
Any maintainer can contest any finding.
Scores are recomputed, not negotiated: if the evidence is wrong the finding goes, and if the code changed a rescan reflects it.

## Surfaces

| Surface | What it is |
|---|---|
| **Site** | Per-server pages with the evidence behind every axis, search and filtering, and the full methodology |
| **JSON API** | The same data, machine-readable — built to be consumed by agents and CI as a first-class audience, not as an afterthought |
| **RSS** | High-severity findings and score drops, for people who want to watch the ecosystem rather than one server |
| **Badges** | An auto-updating SVG a maintainer can put in their own README |
| **CLI** | `pip install mcpwatchman`, then `mcpwatchman check <server>` before you install it — with a `--threshold` exit code for CI |

## Install

```sh
pip install mcpwatchman     # not yet published
```

Requires Python 3.12+.

## Repository layout

```
rules/                 MCP-specific semgrep ruleset, by language and category
src/mcpwatchman/
  cli/                 the `mcpwatchman` command
  api/                 JSON API (FastAPI)
  client/              API client shared by the CLI
  db/                  schema and models
  workers/crawler/     registry polling and source resolution
  workers/scanner/     static analysis and dependency scanning
  workers/scoring/     axis scoring and the versioned weights
evals/gold-set/        hand-audited servers the scoring calibrates against
docker/                worker image
site/                  public site (Astro)
```

## Contributing

It is early, and the most useful contributions right now are adversarial ones: tell us where the methodology is wrong.
Open an issue if a proposed check produces false positives you can demonstrate, if an axis misses a real class of MCP risk, or if a weight looks indefensible.
Rule contributions become genuinely useful once the scanner lands — `rules/` is deliberately open so that the detection logic can be argued with rather than taken on faith.

**Reporting a vulnerability in `mcpwatchman` itself** — not in a server we scan — goes through [GitHub's private vulnerability reporting](https://github.com/kVadrum/mcpwatchman/security/advisories/new) on this repository.
We hold ourselves to the same disclosure terms we apply to everyone else, with no exception for ourselves.

## License

[MIT](./LICENSE).
KeMeK Network © 2026.

### Trademarks

The "mcpwatchman" name is a trademark of KeMeK Network.
It is not covered by the code or content licenses.
No rights to use the name are granted by this repository.
Independent forks must replace the brand name with their own.
