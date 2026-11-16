import type { APIRoute } from "astro";
import { notes } from "../../lib/api-notes";
import { page } from "../../lib/api-pages";

/**
 * The machine surface, and a primary one rather than a courtesy.
 *
 * `CLAUDE.md` is explicit that every surface must be fully readable by humans
 * AND by agents, neither treated as the real audience. This is the same data
 * the pages render, in the shape a program would want it — page 1 of it, with
 * `next` naming the rest (`lib/api-pages.ts`).
 *
 * It carries no composite, for the same reason no page does: the weighted score
 * is computed and withheld until calibration. A consumer that wants one would
 * have to weight the axes itself, and would then own that choice — which is the
 * honest arrangement while ours is unvalidated.
 */
export const GET: APIRoute = () =>
  new Response(JSON.stringify({ ...notes, ...page(1) }, null, 1), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=3600",
    },
  });
