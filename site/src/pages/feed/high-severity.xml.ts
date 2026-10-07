import type { APIRoute } from "astro";
import scans from "../../data/scans.json";
import { findingAnchor, type FindingLike } from "../../lib/findings";

/**
 * `06` §4's high-severity feed, Atom 1.0: critical and high findings that
 * appeared on a page already being tracked, newest first.
 *
 * Generated from the published data like the sitemap, so the feed and the
 * pages cannot disagree. A build cannot see the build before it, so "new" is
 * read from `first_seen`, which publication stamps by comparing each page with
 * the report it replaces (`mcpwatchman.feed`, whose `feed_items` is this
 * endpoint's Python twin and what the build gate checks it against). A null
 * `first_seen` is a page's baseline — there when tracking began — and is
 * never announced.
 *
 * `06` §4's second feed, score drops, is keyed on the composite, which is
 * withheld until calibration, so it is not built.
 */
const BASE = "https://mcpwatchman.com";
const SELF = `${BASE}/feed/high-severity.xml`;
const SEVERITIES = new Set(["critical", "high"]);
const MAX_ENTRIES = 100;

const AXIS_LABEL: Record<string, string> = {
  code_safety: "Code Safety",
  auth_posture: "Auth Posture",
  dependency_health: "Dependency Health",
  maintenance: "Maintenance",
  transparency: "Transparency",
};

type Item = FindingLike & {
  label: string;
  detail: string;
  severity?: string;
  first_seen?: string | null;
  deducts?: boolean;
};

// ⚠ Paths and messages come from scanned repositories, and a file name may
// legally hold a control character XML 1.0 forbids. One such entry would make
// the whole feed unparseable — and the nightly's gate refuses to deploy on
// that, every night it stays in the top 100. Stripped, not escaped: XML has
// no escape for them.
const XML_INVALID =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

const esc = (s: string) =>
  s
    .replace(XML_INVALID, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");

// One entry per finding key, first occurrence kept — the same rule as
// `feed_items`, so the build gate can compare the two entry for entry.
const seenKeys = new Set<string>();
const entries = scans
  .flatMap((report) =>
    Object.entries(report.axes).flatMap(([axis, score]) =>
      (score.evidence as Item[])
        .filter(
          (item) =>
            item.first_seen && SEVERITIES.has(item.severity ?? "") && item.deducts !== false,
        )
        .filter((item) => {
          const key = JSON.stringify([report.slug, axis, item.finding, item.path ?? ""]);
          if (seenKeys.has(key)) return false;
          seenKeys.add(key);
          return true;
        })
        .map((item) => ({ report, axis, item })),
    ),
  )
  .sort(
    (a, b) =>
      (b.item.first_seen ?? "").localeCompare(a.item.first_seen ?? "") ||
      b.report.slug.localeCompare(a.report.slug),
  )
  .slice(0, MAX_ENTRIES);

const tracked = scans
  .map((r) => (r as { findings_tracked_since?: string }).findings_tracked_since)
  .filter((d): d is string => Boolean(d))
  .sort();
const lastScanned = scans.map((r) => r.scanned_at).sort().at(-1) ?? "1970-01-01T00:00:00+00:00";
const updated = entries.length
  ? `${entries[0].item.first_seen}T00:00:00Z`
  : lastScanned;

const subtitle =
  "Critical and high-severity findings that appeared on a server page already " +
  "being tracked, newest first. A page's findings at its first tracked scan are " +
  "its baseline and are not announced" +
  (tracked.length ? `; tracking began ${tracked[0]}.` : "; tracking has not begun yet.");

const entryXml = ({ report, axis, item }: (typeof entries)[number]) => {
  const page = `${BASE}/servers/${report.slug}/`;
  const anchor = findingAnchor(axis, item);
  const href = anchor ? `${page}#${anchor}` : page;
  const where = item.path ? `${item.path}${(item.line ?? 0) > 0 ? `:${item.line}` : ""}` : "";
  const axisLabel = AXIS_LABEL[axis] ?? axis;
  // Stripped BEFORE encoding: a lone surrogate (a non-UTF-8 file name,
  // surrogate-escaped on the Python side) makes encodeURIComponent THROW, which
  // failed the build before `esc` could strip it (Codex leg, 2026-10-07).
  const id = `tag:mcpwatchman.com,2026:${encodeURIComponent(
    `${report.slug}/${axis}/${item.finding}/${item.path ?? ""}`.replace(XML_INVALID, ""),
  )}`;
  const html =
    `<p>${esc(item.detail || item.label)}</p>` +
    (where ? `<p>${esc(where)}</p>` : "") +
    `<p><a href="${esc(href)}">The finding on ${esc(report.name)}'s page</a></p>`;
  return `  <entry>
    <id>${esc(id)}</id>
    <title>${esc(`${report.name}: ${item.severity} ${axisLabel} finding — ${item.finding}`)}</title>
    <updated>${item.first_seen}T00:00:00Z</updated>
    <link rel="alternate" type="text/html" href="${esc(href)}"/>
    <summary>${esc(`${item.severity} ${axisLabel} finding ${item.label}${where ? ` in ${where}` : ""}, first seen ${item.first_seen}.`)}</summary>
    <content type="html">${esc(html)}</content>
  </entry>`;
};

export const GET: APIRoute = () =>
  new Response(
    `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${SELF}</id>
  <title>mcpwatchman — new high-severity findings</title>
  <subtitle>${esc(subtitle)}</subtitle>
  <link rel="self" type="application/atom+xml" href="${SELF}"/>
  <link rel="alternate" type="text/html" href="${BASE}/"/>
  <updated>${updated}</updated>
  <author><name>mcpwatchman</name><uri>${BASE}/</uri></author>
${entries.map(entryXml).join("\n")}
</feed>
`,
    { headers: { "content-type": "application/atom+xml; charset=utf-8" } },
  );
