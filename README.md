# auditmcp

**Independent security and quality audit for [Model Context Protocol](https://modelcontextprotocol.io) servers.**

`auditmcp` continuously scans every server in the official MCP registry and
publishes a transparent, evidence-linked trust score for each one — so you can
answer "is this MCP server safe to install?" before you wire it into your agent.

> **Status: early — building in public.** The methodology and architecture are
> settled; the scanner, scoring engine, site, and CLI are under active
> construction. Nothing here is production-ready yet. Watch the repo (and
> [auditmcp.dev](https://auditmcp.dev), when it's live) to follow along.

---

## Why

MCP adoption is accelerating across Claude Code, Cursor, Continue, Zed, Goose,
and more — and people are installing servers with the same blind trust they once
gave `curl | bash`. Recent research on thousands of public MCP servers found
widespread server-side request forgery, unsafe command execution, and servers
exposed over HTTP with no authentication at all.

The official registry is **metadata-only by design** — it lists what exists, not
what's safe. `auditmcp` is the independent safety layer on top of it. The closest
analogues are [Mozilla Observatory](https://observatory.mozilla.org/) and
[OpenSSF Scorecard](https://scorecard.dev/): independent, transparent, free, and
trusted precisely because they aren't selling anything to the projects they score.

## How it scores

Every server is rated 0–100 on five axes, and **every score links to its
evidence** — a file and line, a CVE ID, a commit date. No mystery numbers.

| Axis | Captures |
|---|---|
| **Code Safety** | Static-analysis findings: shell exec, SSRF, deserialization, path traversal |
| **Auth Posture** | Authentication model, transport security, secret handling |
| **Maintenance** | Activity, release cadence, issue responsiveness, bus factor |
| **Dependency Health** | Known CVEs in direct and transitive dependencies |
| **Transparency** | License validity, documentation, declared scopes |

The full methodology is published openly — anyone can audit our auditing. The
analysis is **static only**: we read published source and lockfiles, and we never
execute the code we scan.

## Principles

- **Methodology over marketing.** Every check, weight, and threshold is documented.
- **Evidence or it doesn't ship.** A finding with no linked artifact doesn't appear.
- **Facts, not characterizations.** We describe observed code patterns, never intent.
  Maintainers can appeal any finding.
- **Collaborative, not competitive.** We overlay the official registry; we don't
  replace it. A server exists here only if the official registry lists it.

## Install

```sh
pip install auditmcp     # coming soon
```

The CLI (`auditmcp check <server>`), public site, JSON API, and RSS feeds are all
free and MIT-licensed, and they stay that way.

## License

[MIT](./LICENSE). KeMeK Network © 2026.

### Trademarks

The "auditmcp" name is a trademark of KeMeK Network. It is not covered by the
code or content licenses. No rights to use the name are granted by this
repository. Independent forks must replace the brand name with their own.
