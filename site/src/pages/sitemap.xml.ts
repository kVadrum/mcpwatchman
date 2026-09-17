import type { APIRoute } from "astro";
import scans from "../data/scans.json";

/**
 * Generated, not hand-maintained.
 *
 * It was a static file in `public/` listing exactly one URL, and the moment
 * forty server pages shipped it was silently wrong — a sitemap that omits the
 * content is worse than none, because it reads as a complete statement of what
 * the site holds. Deriving it from the same data the pages are built from means
 * the two cannot disagree.
 */
const BASE = "https://mcpwatchman.com";

const urls = [
  { loc: `${BASE}/`, priority: "1.0", changefreq: "weekly" },
  { loc: `${BASE}/servers/`, priority: "0.9", changefreq: "daily" },
  ...scans.map((report) => ({
    loc: `${BASE}/servers/${report.slug}/`,
    priority: "0.7",
    changefreq: "weekly",
  })),
];

export const GET: APIRoute = () =>
  new Response(
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls
  .map(
    (u) =>
      `  <url>\n    <loc>${u.loc}</loc>\n    <changefreq>${u.changefreq}</changefreq>\n    <priority>${u.priority}</priority>\n  </url>`,
  )
  .join("\n")}
</urlset>
`,
    { headers: { "content-type": "application/xml; charset=utf-8" } },
  );
