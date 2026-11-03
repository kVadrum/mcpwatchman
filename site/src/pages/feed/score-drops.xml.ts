import type { APIRoute } from "astro";
import scans from "../../data/scans.json";
import { drops } from "../../lib/history";

/**
 * `06` §4's second feed, Atom 1.0. §4 keys it on the composite, which is
 * withheld until calibration, so it is per axis: a fall of 10 or more points
 * on one axis between two consecutive scans of a server.
 *
 * The drops are computed once, in Python (`mcpwatchman.history.drops`, which
 * is canonical for what counts): only between scans under the same scanner,
 * ruleset and methodology with the same measured share — a release changes what
 * is found, not what the server did — and never for Maintenance, whose score
 * decays as time passes and would fill the feed with the calendar
 * (base.md § Signal design). The decay stays on each server's chart.
 */

const BASE = "https://mcpwatchman.com";
const SELF = `${BASE}/feed/score-drops.xml`;
const MAX_ENTRIES = 100;

const AXIS_LABEL: Record<string, string> = {
  code_safety: "Code Safety",
  auth_posture: "Auth Posture",
  dependency_health: "Dependency Health",
  maintenance: "Maintenance",
  transparency: "Transparency",
};

const XML_INVALID =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
const esc = (s: string) =>
  s
    .replace(XML_INVALID, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");

const published = new Set(scans.map((r) => r.slug));
const entries = drops.filter((d) => published.has(d.slug)).slice(0, MAX_ENTRIES);
const measured = (w: string) => `${Math.floor(Number(w) * 100)}% measured`;
const lastScanned = scans.map((r) => r.scanned_at).sort().at(-1) ?? "1970-01-01T00:00:00+00:00";

const entryXml = (d: (typeof entries)[number]) => {
  const page = `${BASE}/servers/${d.slug}/`;
  const axis = AXIS_LABEL[d.axis] ?? d.axis;
  const id = `tag:mcpwatchman.com,2026:drop/${encodeURIComponent(`${d.slug}/${d.axis}/${d.scanned_at}`.replace(XML_INVALID, ""))}`;
  const title = `${d.name}: ${axis} fell ${d.before} → ${d.after} (${measured(d.assessed_weight)})`;
  const html =
    `<p>${esc(`${axis} fell from ${d.before} to ${d.after} between the scans of ${d.previous_scanned_at.slice(0, 10)} and ${d.scanned_at.slice(0, 10)}, under the same scanner, ruleset and methodology, with ${measured(d.assessed_weight)}.`)}</p>` +
    `<p>${esc("A drop is a measurement, not a verdict: the server's page lists the evidence behind the new score.")}</p>` +
    `<p><a href="${esc(page)}">${esc(`${d.name}'s page`)}</a></p>`;
  return `  <entry>
    <id>${esc(id)}</id>
    <title>${esc(title)}</title>
    <updated>${esc(d.scanned_at)}</updated>
    <link rel="alternate" type="text/html" href="${esc(page)}"/>
    <summary>${esc(`${axis} fell ${d.before} → ${d.after} on the scan of ${d.scanned_at.slice(0, 10)}.`)}</summary>
    <content type="html">${esc(html)}</content>
  </entry>`;
};

export const GET: APIRoute = () =>
  new Response(
    `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${SELF}</id>
  <title>mcpwatchman — score drops</title>
  <subtitle>${esc("Falls of 10 points or more on one axis between two consecutive comparable scans of a server, newest first, over the last 90 days. Maintenance is left out: its score decays with time. No composite score is published.")}</subtitle>
  <link rel="self" type="application/atom+xml" href="${SELF}"/>
  <link rel="alternate" type="text/html" href="${BASE}/"/>
  <updated>${esc(entries[0]?.scanned_at ?? lastScanned)}</updated>
  <author><name>mcpwatchman</name><uri>${BASE}/</uri></author>
${entries.map(entryXml).join("\n")}
</feed>
`,
    {
      headers: {
        "content-type": "application/atom+xml; charset=utf-8",
        "cache-control": "public, max-age=3600",
      },
    },
  );
