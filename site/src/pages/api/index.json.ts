import type { APIRoute } from "astro";
import scans from "../../data/scans.json";
import { indexNotes } from "../../lib/api-notes";

/**
 * Every published server in one small document: enough to FIND a server — by
 * registry name, package name or repository — and read its per-axis coverage,
 * without the evidence. The record itself is one request away at `api_url`.
 *
 * ⚠ No score without its `assessed_weight`, here as everywhere: an index is
 * the surface most likely to be skimmed, so it is the last place to drop it.
 * `package` is read defensively because records scanned before the field
 * existed do not carry it; missing means unknown, and is served as "".
 */
const AXIS_KEYS = [
  "code_safety",
  "auth_posture",
  "dependency_health",
  "maintenance",
  "transparency",
] as const;

const servers = scans.map((r) => ({
  name: r.name,
  slug: r.slug,
  version: r.version,
  package: (r as { package?: string }).package ?? "",
  repository_url: r.repository_url,
  registry_state: r.registry_state,
  scanned_at: r.scanned_at,
  url: `https://mcpwatchman.com/servers/${r.slug}/`,
  api_url: `https://mcpwatchman.com/api/servers/${r.slug}.json`,
  axes: Object.fromEntries(
    AXIS_KEYS.map((key) => [
      key,
      {
        score: r.axes[key].score,
        assessed_weight: r.axes[key].assessed_weight,
        fault: r.axes[key].fault,
      },
    ]),
  ),
}));

export const GET: APIRoute = () =>
  new Response(JSON.stringify({ ...indexNotes, count: servers.length, servers }), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=3600",
    },
  });
