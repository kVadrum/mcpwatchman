import type { APIRoute, GetStaticPaths } from "astro";
import scans from "../../../../lib/reports";
import { seriesFor } from "../../../../lib/history";

/**
 * One server's score history — `05` §3.7's relation, `06` §3.1's history
 * endpoint, and what `mcpwatchman trend` draws. Points are scans, oldest
 * first; every score keeps its `assessed_weight`, every point the scanner,
 * ruleset and methodology that produced it, so a reader can mark where scores
 * stop being comparable rather than draw a trend through the seam.
 */
export const getStaticPaths: GetStaticPaths = () =>
  scans.map((server) => ({ params: { slug: server.slug }, props: { server } }));

export const GET: APIRoute = ({ props }) =>
  new Response(
    JSON.stringify(
      {
        note:
          "Each point is one recorded scan; a day with no point is a night this server was not measured, never a day its score held. " +
          "Scores under different scanner, ruleset or methodology versions are different measurements. " +
          "A score is the share of what could be measured — read it with its assessed_weight; null means not assessed, never zero.",
        slug: props.server.slug,
        name: props.server.name,
        url: `https://mcpwatchman.com/servers/${props.server.slug}/`,
        points: seriesFor(props.server),
      },
      null,
      1,
    ),
    {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "public, max-age=3600",
      },
    },
  );
