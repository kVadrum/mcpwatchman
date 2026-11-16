// The published reports, from whichever store layout is present — the site's
// half of `mcpwatchman.store` (operator ruling D2a, 2026-11-09: one file per
// server, so no file nears GitHub's limits at 5,000).
//
// ⚠ Every page imports from HERE, never from `../data/scans.json`: a static
// import of a file that is gone fails the build, and the move between layouts
// is expand-then-contract because the nightly builds `main`'s pages over
// `dev`'s data. A glob of a missing path is just empty.
//
// The type comes from a type-only import, which the build erases, so it costs
// nothing once the monolith is gone; replace it with a declared type then.
import type monolith from "../data/scans.json";

export type Report = (typeof monolith)[number];

const mono = Object.values(
  import.meta.glob<Report[]>("../data/scans.json", { eager: true, import: "default" }),
);
const split = Object.values(
  import.meta.glob<Report>("../data/reports/*.json", { eager: true, import: "default" }),
);

if (mono.length > 0 && split.length > 0) {
  // Either answer would publish one layout's pages over the other's silently.
  throw new Error("both scans.json and reports/ exist: a half-finished move between layouts");
}
if (mono.length === 0 && split.length === 0) {
  // Two empty globs are an empty list, and an empty list builds: an index, an
  // API and a sitemap with nothing in them, and no server pages — every
  // published URL unpublished by a build that succeeds. Workers Builds deploys
  // a sync with no gate but `npm run build`, so this throw is that gate.
  // Neither layout is malformed data, as it is for `mcpwatchman.store`.
  throw new Error("neither scans.json nor reports/ exists: refusing to build a site with no reports");
}

// Shards in the monolith's own order (by name, as `ops/scan_cohort.py` writes
// it), compared by code unit, never by locale, so the pages cannot tell which
// layout they were built from.
const byName = (a: Report, b: Report) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

const reports: Report[] = mono.length > 0 ? mono[0] : [...split].sort(byName);

export default reports;
