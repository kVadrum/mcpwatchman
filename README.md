# mcpwatchman

**Independent security and quality audit for [Model Context Protocol](https://modelcontextprotocol.io) servers.**

`mcpwatchman` rescans servers listed in the official MCP registry every night and publishes a transparent, evidence-linked assessment of each one — so you can answer "is this MCP server safe to install?" before you wire it into your agent.

**[mcpwatchman.com](https://mcpwatchman.com)** — every published server, the evidence behind each score, and a worked example of how a score is built.

> **Status: pre-alpha, and live.**
> 492 servers are published and rescanned nightly, each with per-axis scores and the evidence behind every deduction.
> The scores are **uncalibrated**: there is no composite score, and no rule may claim high confidence, until a hand-audited gold set is ratified — and none of it has been yet.
> The published set is a sample of about 1% of the registry, not the registry.
> [What exists today](#what-exists-today) separates what is live from what is partial and what is only specified.

---

## What exists today

| | Status |
|---|---|
| Nightly rescan of the published set | **Live** since 2026-09-30, about an hour per run |
| Per-server pages, static JSON API, `llms.txt`, sitemap | **Live** |
| Atom feed of new critical and high findings | **Live**; findings are dated from 2026-10-10, when tracking began |
| `mcpwatchman check` CLI | **Live** on [PyPI](https://pypi.org/project/mcpwatchman/) |
| Per-axis scores | **Live, uncalibrated** — every finding is capped at medium confidence |
| Weighted composite score | **Withheld** — computed, published nowhere, until calibration |
| Gold set for calibration | **Partial** — 30 servers drafted, none of the 25 required ratified |
| Remote-only servers (no published source) | **Mostly absent** — 8 are published, but growth only draws servers that declare a source |
| Automated maintainer notification | **Not built** — see [Disclosure](#disclosure) |
| Sandboxed scan workers | **Not built** — see [Isolation](#isolation) |
| Query API backed by a database | **Scaffold** — a FastAPI health probe and an empty schema; the server it would run on is not provisioned |
| Site search and filtering, score-drops feed, README badges | **Not built** |

## Why

MCP adoption is accelerating across Claude Code, Cursor, Continue, Zed, Goose and more — and people are installing servers with the same blind trust they once gave `curl | bash`.

The measured picture is not reassuring, and it is worth being precise about who measured what:

- A 2026 measurement study of **7,973 live remote MCP servers** found [**40.55% expose tools with no authentication at all**](https://arxiv.org/abs/2605.22333).
  Of the 119 servers with testable OAuth deployments, *every one* carried at least one authentication flaw.
- A survey of [**8,060 servers across six registries**](https://arxiv.org/abs/2509.25292) found fewer than half of listed projects valid or non-trivial, and 21.9% with no update in over a year.
- Vendor scans have reported SSRF patterns in roughly a third of servers and command-injection paths in over 40% (BlueRock, Equixly).
  We cite these as motivation, not as fact: their sample construction and false-positive rates are unpublished, the firms reporting them sell products in this space, and the BlueRock page we first cited for them now returns 404.

That last bullet is the whole problem in miniature — the numbers everyone quotes come from parties with something to sell, and nobody can check them.
`mcpwatchman` publishes its rules and its evidence, so ours can be checked.
It will publish each rule's measured false-positive rate once the gold set is ratified; none has been measured yet, which is exactly why no rule is allowed to claim high confidence.

The official registry is **metadata-only by design** — it lists what exists, not what's safe.
`mcpwatchman` is an independent safety layer on top of it.
The closest analogues are [Mozilla Observatory](https://observatory.mozilla.org/) and [OpenSSF Scorecard](https://scorecard.dev/): independent, transparent, free, and trusted precisely because they aren't selling anything to the projects they score.

## How it works

Every night at 02:00 UTC, `ops/nightly.sh` (run by the systemd units in `ops/systemd/`) does this for the published set:

1. **Crawl** the full registry listing, so a server the registry has deprecated or delisted is labelled as such rather than silently rescanned.
2. **Resolve** each server's declared source — a Git repository, or an npm or PyPI package — from its registry metadata.
3. **Fetch** it: a shallow (`--depth 1`) clone, sparse when the server lives in a subfolder, with a release resolved through its tag; or the published package archive, unpacked under size and member caps.
4. **Analyze statically** — an MCP-specific [semgrep](https://semgrep.dev) ruleset for Go, JavaScript/TypeScript and Python (shell exec, SSRF, unsafe deserialization and path traversal in all three, plus prototype pollution in JavaScript and SQL injection in Python); [osv-scanner](https://google.github.io/osv-scanner/) for known vulnerabilities in pinned dependencies; detect-secrets for committed credentials; transport and authentication inspection; licence, README, changelog and security-contact checks; and maintenance signals from the GitHub API.
5. **Score** each axis from those findings, with every point traceable to the artifact that produced it.
6. **Gate and publish** — the run refuses to publish if any repository it scored is private, the publication tests run against the freshly built site, the data is committed to `dev`, and the site is deployed to Cloudflare Workers.

**The scanner runs from `main`; the data comes from `dev`.**
`main` moves only when the maintainer reviews `dev` and fast-forwards it by hand, so a scanner change cannot publish statements about third parties overnight without that step, while `dev` holds the running record of what has been published.
That review is this project's practice; nothing on GitHub requires it yet.
A run in which too many servers could not be measured on our side — more than `max(5, 10%)` of the set — refuses to write, so our own outage never reaches a public page dressed as a finding.

**The analysis is static, always.**
We read published source, manifests and lockfiles.
**We never execute the code we scan**, and we never connect to a running server instance.

**So here is what a good score cannot tell you.**
Static analysis reads what a server *publishes*, so the blind spot is whatever that source does not determine: behavior gated on remote configuration, code fetched or generated at runtime, or a deployed server that differs from the repository it declares.
An unsafe pattern that merely *executes* at tool-invocation time is still detectable — catching those is the ruleset's core job — but a score here is evidence about published source, never a runtime guarantee.
Running every server we scan is a substantially larger sandboxing problem than reading it, and we would rather be narrow and honest about it than broad and quietly wrong.

### Isolation

**The scan does not run in a sandbox yet.**
It runs as an ordinary unprivileged process at low CPU and I/O priority on the maintainer's own machine — not in a container, and not network-isolated — so it can read whatever that user can.
What keeps that narrow is that nothing fetched is ever executed: no install scripts, no builds, no tests, no git hooks.

**The scan reads third-party code without the maintainer's credentials.**
Git runs with no user or system configuration, so no credential helper and no URL rewrite reaches a clone, and every tool the scan starts — git, semgrep, osv-scanner, detect-secrets — gets an allowlisted environment that carries no tokens.
The one credentialed call is the GitHub API lookup behind Maintenance, and it refuses any repository GitHub does not report as public; the nightly then checks once more, before anything is published, that no repository it scored is private.
**That was not always so.**
Until v0.38.4 (2026-10-19) the scanner's git inherited the maintainer's configuration, credential helper included, so a registry entry naming a private repository the maintainer could read would have been cloned with their credentials and its contents scored in public, and the Maintenance lookup would have read its activity with their token.
A review of every published server found no page that drew on a repository only those credentials could read.

The bounds that exist are in-process: an archive is capped at 512 MiB unpacked and 50,000 members; a cloned tree is checked against 512 MiB and 250,000 entries from git's own listing before any file is written (for a sparse clone, its entry count — its bytes are measured after); every path is confined to the scan's scratch directory; and scanner configuration shipped inside a scanned repository (a `.semgrepignore`, for instance) is deleted before the scan, because it is attacker input too.
The nightly's systemd unit adds what an unprivileged service can enforce — no privilege escalation, no new namespaces, no setuid files, network, local and netlink sockets only — which narrows a compromise without containing one.
A sandboxed worker is specified; `docker/` holds a scaffold of its image, which the nightly does not use.

### Coverage

**The registry is large, and we publish a sample of it.**
The registry's full listing on 2026-10-19 held about 45,000 active entries; `mcpwatchman` publishes 492 of them.
The set is **pinned and append-only** — a server that gets a page keeps it at a stable URL, and the set only grows.
It is **not representative**: the first servers published were drawn from the registry's alphabetical head, everything added since is drawn in hash order across the whole registry, and growth only picks servers that declare a source.
Don't infer anything from a server's absence — it means we have not published it, never that it was judged.

**Remote-only servers are almost entirely absent**, so the hardest part of the registry to assess is the part this set leaves out.
Eight are published — URLs that predate the pinned set and were kept so they would not break — and growth never adds another.
In a 100-server sample taken on 2026-09-14, 48 of the 99 active servers were remote-only — an endpoint with no published source — and 50 declared a source.
Declaring a source is not the same as it being readable: in a separate 200-entry sample on 2026-09-15, 43 of the 95 entries declaring a repository (45.3%) were not publicly reachable.
GitHub answers 404 for a private repository as well as a missing one, so that figure means "we could not read it", never "it does not exist".

**Of the 492 published servers**, as of the 2026-10-19 scan, 428 shipped source we read, 52 declare a repository that is not publicly reachable, 4 name a package we could not fetch from its registry, and 8 declare no source at all.
Current figures are on [the homepage](https://mcpwatchman.com) and in [`/llms.txt`](https://mcpwatchman.com/llms.txt).

We are deliberately *not* claiming that unreadable servers are the dangerous ones.
That would be an appealing inference and an unsupported one: the authentication study cited above found its servers by internet-wide scanning, not from this registry, so its population and this one overlap without being the same — and no correlation between "ships no source" and "unauthenticated" has been measured by anyone, us included.

## How it scores

Every server is rated 0–100 on five axes, independently, and **every score links to its evidence** — a file and line, a vulnerability identifier, a commit date.
No mystery numbers.

| Axis | Weight (provisional) | How it is scored |
|---|---|---|
| **Code Safety** | 30% | Opens at 100; each semgrep finding deducts by its severity and confidence |
| **Auth Posture** | 20% | Weighted sub-checks: authentication model, transport security, secret handling, authorization granularity |
| **Dependency Health** | 20% | Opens at 100; each known vulnerability deducts by its severity and whether the dependency is direct or transitive |
| **Maintenance** | 15% | Weighted sub-checks: recency, issue responsiveness, release cadence, bus factor, repository signals |
| **Transparency** | 15% | Weighted sub-checks: licence, README quality, declared scopes, changelog, security contact |

On the two deduction axes, findings of the same severity stack with diminishing returns: the worst takes its full deduction, the next 75%, then 50%, 25%, and 10% for every one after that — so twenty criticals don't score like one, and one critical still takes the undiminished hit.
The weights, sub-check weights and deduction tables live in [`src/mcpwatchman/workers/scoring/`](https://github.com/kVadrum/mcpwatchman/tree/main/src/mcpwatchman/workers/scoring) and are versioned with the methodology (currently `0.2.0`).

**A score never travels without its `assessed_weight`** — the share of the axis that could actually be measured.
A score of 80 at an `assessed_weight` of 0.25 is 80 of a quarter of an axis, not 80.
A `null` score means *not assessed*, never zero; they are opposite claims about a server.
Where the methodology defines no band, the sub-check abstains rather than inventing one: authorization granularity is never scored yet, nor is repository signals, which needs a distribution across every scanned server that is not computed.
Dependency Health needs a lockfile or exact version pins, so most servers go unscored on it.

**The scores are uncalibrated, and the code enforces what that means.**
No semgrep rule may claim high confidence, because the methodology defines that tier as a false-positive rate measured against a gold set — so every finding is capped at medium, and no deduction is yet as large as a calibrated high-confidence one would be.
Calibration can move a score either way: a rule measured as reliable can deduct more, and one measured as noisy less, or be withdrawn.
The weighted composite is computed but published nowhere: not on the site, not in the API, not in the CLI.
Both gates open only once at least 25 hand-audited gold-set servers are ratified; 30 have been drafted and none ratified.
A single blended number is the easiest thing to publish and the easiest thing to get quietly wrong, so it is the last thing we will ship.

**What is public about the method:** the code that computes every score and the ruleset it runs are in this repository, and the site and `/llms.txt` explain them in prose.
The full methodology document that code implements is not published yet.

## Principles

- **Methodology over marketing.**
  Every check, weight and threshold is in versioned code.
- **Evidence or it doesn't ship.**
  A finding with no linked artifact doesn't appear.
- **Facts, not characterizations.**
  We describe observed code patterns, never intent.
  Any finding can be appealed.
- **Collaborative, not competitive.**
  We overlay the official registry; we don't replace it.
  A server is published here only if the official registry lists it, or listed it — a server the registry later drops keeps its last page, marked as delisted.
- **Free, and staying that way.**
  The scanner, ruleset, published data, JSON API, feed and CLI are MIT-licensed; the site's text is CC BY 4.0.

## Disclosure

Findings fall into two tracks, and they are handled differently on purpose.

**Track A — publicly observable patterns.**
Static-analysis hits, license and transport facts: anyone can run the same tools against the same published source and see the same thing.
There is no informational asymmetry to protect, so these are **not embargoed** — they appear on the server's page from the first scan that detects them.

**Not yet in place: maintainer notification.**
The policy calls for an automated notice to the maintainer's documented contact when a high or critical Track A finding is published.
That notification is not built — such findings currently appear on the server's page and in the feed without any maintainer being contacted.

**Track B — findings that warrant coordination.**
Default embargo is **14 days** from maintainer contact, shortened to **7** where there is evidence of active exploitation, and extended up to **45 days total** when a maintainer comes back with a concrete fix timeline.
If we cannot reach a maintainer within 48 hours of the first attempt the clock still starts, and the target becomes **21 days from that first attempt** rather than 14 — being slow to check email is not the same as being unresponsive, and we don't punish it.

**Appeals.**
Anyone can contest a finding — maintainers and third parties alike — by opening [an issue](https://github.com/kVadrum/mcpwatchman/issues) that links the finding on the server's page.
Scores are recomputed, not negotiated: if the evidence is wrong the finding goes, and if the code changed a rescan reflects it.
A finding that is technically valid but mitigated by context our rules don't model stays on the page; there is no field yet for a maintainer's response, so the issue thread is the record of it.

## Surfaces

The site, JSON API, feed, `llms.txt` and sitemap are all generated from one data file at each nightly build, so they cannot disagree, and the CLI reads that same JSON.

| Surface | What it is |
|---|---|
| **Site** | Per-server pages with the evidence behind every axis, and an index of all of them — [mcpwatchman.com/servers/](https://mcpwatchman.com/servers/). No search or filtering yet |
| **JSON API** | Static files, built for agents and CI as a first-class audience: `/api/servers/<slug>.json` per server, `/api/index.json` to find one, `/api/servers.json` for everything. There is no query API yet |
| **Feed** | [`/feed/high-severity.xml`](https://mcpwatchman.com/feed/high-severity.xml) (Atom) — critical and high findings that newly appeared on a page already being tracked. A server's first tracked scan is its baseline and is never announced |
| **Agents** | [`/llms.txt`](https://mcpwatchman.com/llms.txt), `/robots.txt` (no crawler is blocked), `/sitemap.xml`, `/.well-known/security.txt` |
| **CLI** | `pip install mcpwatchman`, then `mcpwatchman check <server>` before you install it |

Specified but not built: a score-drops feed (it reports the composite, which is withheld) and an auto-updating SVG badge for a maintainer's own README.

## Install

```sh
pip install mcpwatchman
mcpwatchman check io.github.owner/server           # a registry name or slug
mcpwatchman check @scope/package --format json     # an npm or PyPI name, or a repository URL
```

Requires Python 3.12+.
`check` reads the same static JSON the site publishes; set `MCPWATCHMAN_API_URL` to point it elsewhere.
`--format` is `pretty` (default), `json` or `compact`, and `--version <v>` refuses to answer for any server version other than the one published.
Every score is printed with the share of its axis that could actually be measured, and there is no composite number — so `--threshold` is accepted but does nothing until the composite is published, and says so.
Exit codes: `0` found, `1` not published (or not at the version asked for), `4` network error, `5` bad arguments; `2` is reserved for a failed threshold.

### Running a scan yourself

Anyone can rerun the scan, and it reproduces the method rather than any one night's numbers: its Python dependencies are locked with hashes, but each run reads the live registry, each repository as it stands that day, and the live GitHub API.
It needs three scanner binaries — `semgrep` and `detect-secrets`, which the locked requirements install, and `osv-scanner`, a Go binary you install yourself — plus a GitHub token.
All three are resolved on `PATH`, so installing them into a venv is not enough — the venv's `bin` has to be on `PATH` when the scan runs.

```sh
python -m venv .venv-workers
.venv-workers/bin/pip install --require-hashes -r requirements/workers.txt   # semgrep, detect-secrets, ...
.venv-workers/bin/pip install --no-deps -e .
# osv-scanner is a Go binary; take the release that matches your platform and
# verify it against the published SHA256SUMS
curl -sSLO https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64
install -m 0755 osv-scanner_linux_amd64 .venv-workers/bin/osv-scanner

# Maintenance reads the GitHub API. Without a token the scan refuses to start:
# every server would go unassessed for our reason, and every page would silently
# keep its previous scan.
export MCPWATCHMAN_GITHUB_TOKEN=...                 # or GITHUB_TOKEN

# Preview the plan — what would be scanned, carried forward, or grown.
# `--dry-run` still crawls the whole registry (several minutes), then returns
# BEFORE scanning anything and writes no data.
PATH="$PWD/.venv-workers/bin:$PATH" .venv-workers/bin/python ops/scan_cohort.py \
    --out site/src/data/scans.json --dry-run

# The actual scan. Drop `--dry-run` — this one rewrites the published data, and
# on the current set it takes about an hour.
PATH="$PWD/.venv-workers/bin:$PATH" .venv-workers/bin/python ops/scan_cohort.py \
    --out site/src/data/scans.json
```

Run it on a quiet machine.
A scan's failure rate is dominated by concurrent load rather than by the repository being scanned: measured 2026-09-18, 3 of 29 servers came back unmeasurable while a test run and a second scan shared the box, against 0 of 492 on an idle one.

**A missing binary does not fail — it produces a clean "not assessed".**
Code Safety carries 30% of the weighting and Dependency Health 20%, so a scan run without them publishes a page that looks measured and is not.
`ops/scan_cohort.py` refuses to start rather than let that happen.
semgrep is pinned in `requirements/workers.txt` (1.179.0), and the osv-scanner release the dependency check was written against is recorded in `workers/scanner/osv_check.py` (2.6.0).

## Development

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest
```

The tests that read the built site skip without one, and read whatever was built last when there is one — run `npm ci && npm run build` in `site/` first, and again after pulling new data.
The tests that drive the real scanner binaries skip unless the `[workers]` toolchain is on `PATH`.
CI runs four jobs on every push to `dev` and `main`: `lint` (ruff, mypy), `test` (`[dev]` only, no built site), `site` (builds the site, then runs the suite against it) and `workers-extra` (the hash-locked `requirements/workers.txt` plus `[dev]`, with the real semgrep and detect-secrets).

## Repository layout

```
rules/                 semgrep ruleset — go, javascript (covers TypeScript), python
src/mcpwatchman/
  cli/                 the `mcpwatchman` command; reads the static JSON API
  workers/crawler/     registry crawl and source resolution; queue planning,
                       not yet connected to a queue
  workers/scanner/     fetch, semgrep, osv-scanner, detect-secrets, and the
                       auth, transport, licence, maintenance checks
  workers/scoring/     axis scoring, stacked deductions, versioned weights
  cohort.py            the pinned, append-only published set
  feed.py              first-seen dating behind the Atom feed
  goldset.py           gold-set loading and the ratification gate
  api/                 FastAPI scaffold — a health probe only
  db/                  SQLAlchemy base only — no schema or migrations yet
  client/              empty placeholder
ops/                   scan driver, nightly wrapper and systemd units,
                       calibration tools, cohort.json (the published set)
site/                  Astro site; also generates the JSON API, feed,
                       llms.txt and sitemap from site/src/data/scans.json
tests/                 pytest suite
evals/gold-set/        gold-set format; no ratified entries yet
docker/                worker-image scaffold, not used by the nightly
```

## Reporting a problem

**A vulnerability in mcpwatchman itself** — the site, the CLI, the scanner or the published package — goes to [GitHub's private advisory form](https://github.com/kVadrum/mcpwatchman/security/advisories/new).
Private vulnerability reporting is enabled on this repository, so the report is not public while it is being fixed, and we hold ourselves to the same disclosure terms we apply to everyone else.
`/.well-known/security.txt` carries the same addresses in machine-readable form.

**A mistake in the methodology or a wrong number** goes to [the issue tracker](https://github.com/kVadrum/mcpwatchman/issues), in public.
These are the most useful contributions right now: several figures in this README have already been corrected after being checked against their sources, and a methodology that cannot be audited is the thing this project exists to replace.

**A vulnerability in an MCP server that mcpwatchman scores is not ours to receive.**
Report it to that server's maintainer.
If you believe we have scored a server wrongly — a false positive, a finding already fixed, a rule misfiring — open an issue and we will correct it and say that we did.
When we find something in a server that warrants coordination, we follow the Track B process above before publishing: the maintainer is contacted first and given a remediation window, and the schedule is documented rather than improvised.

## Contributing

It is early, and the most useful contributions are adversarial ones: tell us where the methodology is wrong.
Open an issue if a check produces false positives you can demonstrate, if an axis misses a real class of MCP risk, or if a weight looks indefensible.
The scanner is running, and `rules/` is deliberately open so that the detection logic can be argued with rather than taken on faith — a rule change that comes with a fixture it should fire on, and a look-alike it must not, is the most useful kind.

## License

This repository is dual-licensed:

- **Code** — the scanner, the scoring engine, the semgrep ruleset, the CLI, the website's source and the published scan data — [MIT](https://github.com/kVadrum/mcpwatchman/blob/main/LICENSE).
  Excerpts the scan data quotes from scanned servers' source remain their authors'.
- **The website's prose** — the text of [mcpwatchman.com](https://mcpwatchman.com), its worked example of how a score is built included — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **Names and marks** — the "mcpwatchman" name and mark are not licensed; see below.

KeMeK Network © 2026.

### Names and marks

The "mcpwatchman" name and mark are not covered by the code or content licenses.
KeMeK Network reserves all rights in them.
Independent forks must replace the name and mark with their own.
