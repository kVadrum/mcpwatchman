import type { APIRoute } from "astro";
import data from "../../data/methodology-changes.json";

/**
 * Announced methodology changes, Atom 1.0: the announcement `03` §11 asks for
 * before a minor or major version deploys. It reads the same file as the
 * methodology page and `tests/test_methodology_changes.py`, which holds each
 * entry to §11's notice period.
 */

const BASE = "https://mcpwatchman.com";
const SELF = `${BASE}/feed/methodology.xml`;
const PAGE = `${BASE}/methodology/#announced-heading`;

const esc = (s: string) =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");

const changes = [...data.changes].sort((a, b) => b.announced.localeCompare(a.announced));
const stamp = (day: string) => `${day}T00:00:00Z`;

const entryXml = (c: (typeof changes)[number]) => {
  const html =
    `<p>${esc(`${c.level === "major" ? "Major" : c.level === "minor" ? "Minor" : "Patch"} version ${c.version}, announced ${c.announced}. It takes effect no earlier than ${c.not_before}.`)}</p>` +
    c.points.map((p) => `<p>${esc(p)}</p>`).join("");
  return `  <entry>
    <id>tag:mcpwatchman.com,2026:methodology/${esc(c.version)}</id>
    <title>${esc(`Methodology ${c.version}: ${c.title}`)}</title>
    <updated>${stamp(c.announced)}</updated>
    <link rel="alternate" type="text/html" href="${PAGE}"/>
    <summary>${esc(`${c.summary} Not before ${c.not_before}.`)}</summary>
    <content type="html">${esc(html)}</content>
  </entry>`;
};

export const GET: APIRoute = () =>
  new Response(
    `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${SELF}</id>
  <title>mcpwatchman — methodology changes</title>
  <subtitle>${esc("Changes to the scoring methodology, each announced before it takes effect: 14 days ahead for a minor version, 30 for a major one.")}</subtitle>
  <link rel="self" type="application/atom+xml" href="${SELF}"/>
  <link rel="alternate" type="text/html" href="${BASE}/methodology/"/>
  <updated>${stamp(changes[0]?.announced ?? "2026-09-01")}</updated>
  <author><name>mcpwatchman</name><uri>${BASE}/</uri></author>
${changes.map(entryXml).join("\n")}
</feed>
`,
    {
      headers: {
        "content-type": "application/atom+xml; charset=utf-8",
        "cache-control": "public, max-age=3600",
      },
    },
  );
