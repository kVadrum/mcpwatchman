import type { APIRoute, GetStaticPaths } from "astro";
import { notes } from "../../../../lib/api-notes";
import { PAGE_COUNT, page } from "../../../../lib/api-pages";

/**
 * Pages 2 onward of the full records; page 1 is `/api/servers.json`. While
 * every record fits on page 1 this route builds nothing at all.
 */
export const getStaticPaths: GetStaticPaths = () =>
  Array.from({ length: PAGE_COUNT - 1 }, (_, i) => ({ params: { n: String(i + 2) } }));

export const GET: APIRoute = ({ params }) =>
  new Response(JSON.stringify({ ...notes, ...page(Number(params.n)) }, null, 1), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=3600",
    },
  });
