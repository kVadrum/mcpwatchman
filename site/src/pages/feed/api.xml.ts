import type { APIRoute } from "astro";
import data from "../../data/api-changes.json";

/**
 * Announced changes to the JSON API, Atom 1.0. It reads the same file as the
 * `/api/` page and the `api_changes` field of every JSON response, and
 * `tests/test_api_changes.py` holds each entry to its notice period: 30 days
 * for a breaking change.
 */

const BASE = "https://mcpwatchman.com";
const SELF = `${BASE}/feed/api.xml`;

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
    `<p>${esc(`A ${c.level} change, announced ${c.announced}. It takes effect no earlier than ${c.not_before}.`)}</p>` +
    c.points.map((p) => `<p>${esc(p)}</p>`).join("");
  return `  <entry>
    <id>tag:mcpwatchman.com,2026:api/${esc(c.id)}</id>
    <title>${esc(`API: ${c.title}`)}</title>
    <updated>${stamp(c.announced)}</updated>
    <link rel="alternate" type="text/html" href="${BASE}/api/#api-change-${esc(c.id)}"/>
    <summary>${esc(`${c.summary} Not before ${c.not_before}.`)}</summary>
    <content type="html">${esc(html)}</content>
  </entry>`;
};

export const GET: APIRoute = () =>
  new Response(
    `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${SELF}</id>
  <title>mcpwatchman — API changes</title>
  <subtitle>${esc("Changes to the JSON API, each announced before it takes effect: 30 days ahead for a breaking change.")}</subtitle>
  <link rel="self" type="application/atom+xml" href="${SELF}"/>
  <link rel="alternate" type="text/html" href="${BASE}/api/"/>
  <updated>${stamp(changes[0]?.announced ?? "2026-11-16")}</updated>
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
