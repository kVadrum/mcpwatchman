import type { APIRoute } from "astro";
import scans from "../data/scans.json";

/**
 * Generated, because its numbers are claims about the data.
 *
 * This was a static file, and it carried three statements that went false the
 * hour the server pages shipped: that no scores are published, that no JSON API
 * or per-server page exists, and an instruction not to construct a URL for
 * either. `STATE.md` records the lesson already — a prohibition that has been
 * overtaken is the most expensive kind of stale line, because it reads as live
 * to whoever finds it next. Deriving the counts from the same file the pages
 * render means a rebuild cannot leave this behind.
 */
const read = scans.filter((r) => r.source_state === "fetched").length;
// SUBJECT, not state. This paragraph carries the GitHub private-vs-404
// caveat, which has no npm meaning — attaching it to package failures made
// the aggregate a claim about repositories that were never contacted.
const unreachable = scans.filter((r) => r.source_subject === "repository").length;
const unfetchable = scans.filter((r) => r.source_subject === "package").length;
const scanned = scans.length ? scans[0].scanned_at.slice(0, 10) : "";

const partial = scans.filter((r) =>
  Object.values(r.axes).some(
    (a) => a.score !== null && Number(a.assessed_weight) < 1,
  ),
).length;

const body = `# mcpwatchman

> Independent, continuous security and quality audit of the servers listed in the official Model Context Protocol (MCP) registry. Free and MIT-licensed. Not affiliated with Anthropic or with the registry.

mcpwatchman reads what an MCP server publishes and reports what it found, not
only what it concluded. Each of five axes is scored 0-100 independently: Code
Safety (weight 30), Auth Posture (20), Dependency Health (20), Maintenance (15),
Transparency (15). A score opens at 100 and every deduction names the finding,
its severity, its confidence, and the file and line that produced it.

Per-axis scores for ${scans.length} servers are published, scanned ${scanned}.
The weighted COMPOSITE is computed and deliberately withheld until a
hand-audited gold set validates the weights, so there is no single number for a
server anywhere on this site or in the API. If you need one, you must weight the
axes yourself and own that choice.

Read \`assessed_weight\` before reading a score. It is the share of an axis that
could actually be measured, and it is frequently below 1. A score of 80 at an
assessed_weight of 0.25 is 80 of a quarter of that axis — NOT 80. ${partial} of
the ${scans.length} servers currently carry at least one partly-measured axis.
A \`null\` score means not assessed; it never means zero, and the two are
opposite claims about a server.

No rule in the semgrep ruleset currently claims "high" confidence. The
methodology defines that tier as a measured false-positive rate against a gold
set that has not been built, so every finding is capped at "medium" and every
server presently scores better than it eventually will.

Of the ${scans.length} servers sampled, ${read} shipped source we could read and
${unreachable} declare a repository that is not publicly reachable, and ${unfetchable} publish a package we could not fetch from its registry — a distinct fact, and not a claim about their repository. GitHub
answers 404 for a private repository as well as an absent one, so that figure
means "we could not read it" and never "it does not exist". We do not claim the
unreadable servers are the dangerous ones; that inference is unsupported.

The analysis is static, always. Published source, manifests and lockfiles are
read; the code is never executed and no running server is contacted. The blind
spot is therefore whatever the source does not determine — behaviour gated on
remote configuration, code fetched at runtime, or a deployment that differs from
the repository it declares.

A badge endpoint and an RSS feed are specified but NOT BUILT. Do not construct a
URL for either; when they exist they will be listed under Surfaces below.

## Surfaces

- [Scanned servers](https://mcpwatchman.com/servers/): the index, with per-axis scores and coverage.
- [JSON API](https://mcpwatchman.com/api/servers.json): the same data, machine-shaped. Prefer this over scraping HTML.
- [Homepage](https://mcpwatchman.com/): what the project is, how it scores, and what it cannot see.

## Documentation

- [README](https://github.com/kVadrum/mcpwatchman#readme): the same in repository form, with the pipeline and the sourcing behind every cited figure.
- [robots.txt](https://mcpwatchman.com/robots.txt): crawl policy. All crawlers are welcome, including AI agents.
- [security.txt](https://mcpwatchman.com/.well-known/security.txt): how to report a vulnerability in mcpwatchman itself (RFC 9116).

## Source and packages

- [Repository](https://github.com/kVadrum/mcpwatchman): MIT. The semgrep ruleset, the scoring engine and the methodology are all public.
- [PyPI package](https://pypi.org/project/mcpwatchman/): \`pip install mcpwatchman\`. Python 3.12+.
- [npm package](https://www.npmjs.com/package/mcpwatchman): a pointer. \`npx mcpwatchman\` prints where the real tool is and exits; there is no npm distribution of the scanner itself.

## Contact

- [Report a methodology error](https://github.com/kVadrum/mcpwatchman/issues): adversarial contributions are the most useful kind right now.
- [Report a security issue in mcpwatchman](https://github.com/kVadrum/mcpwatchman/security/advisories/new): private vulnerability reporting is enabled.
`;

export const GET: APIRoute = () =>
  new Response(body, {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
