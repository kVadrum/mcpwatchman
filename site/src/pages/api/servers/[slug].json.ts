import type { APIRoute, GetStaticPaths } from "astro";
import scans from "../../../data/scans.json";
import { notes } from "../../../lib/api-notes";

/**
 * One server, at the URL its page already promises: `/servers/<slug>/` has a
 * machine twin at `/api/servers/<slug>.json`.
 *
 * The full `/api/servers.json` is one multi-megabyte document; an agent or the
 * CLI asking about one server before installing it should not have to fetch
 * every other server to read it. Same record, same reading instructions — the
 * notes travel with every response because a score is only honest beside the
 * rules for reading it.
 */
export const getStaticPaths: GetStaticPaths = () =>
  scans.map((server) => ({ params: { slug: server.slug }, props: { server } }));

export const GET: APIRoute = ({ props }) =>
  new Response(
    JSON.stringify(
      {
        ...notes,
        url: `https://mcpwatchman.com/servers/${props.server.slug}/`,
        server: props.server,
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
