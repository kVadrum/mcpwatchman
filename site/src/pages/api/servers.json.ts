import type { APIRoute } from "astro";
import scans from "../../data/scans.json";

/**
 * The machine surface, and a primary one rather than a courtesy.
 *
 * `CLAUDE.md` is explicit that every surface must be fully readable by humans
 * AND by agents, neither treated as the real audience. This is the same data
 * the pages render, in the shape a program would want it.
 *
 * It carries no composite, for the same reason no page does: the weighted score
 * is computed and withheld until calibration. A consumer that wants one would
 * have to weight the axes itself, and would then own that choice — which is the
 * honest arrangement while ours is unvalidated.
 */
export const GET: APIRoute = () =>
  new Response(
    JSON.stringify(
      {
        generator: "mcpwatchman",
        composite_published: false,
        composite_note:
          "No composite score is published. The five axes are weighted 30/20/20/15/15 and the weighted score is computed, but it stays withheld until a hand-audited gold set validates those weights.",
        coverage_note:
          "`assessed_weight` is the share of an axis that could actually be measured. A score of 80 at an assessed_weight of 0.25 is 80 of a quarter of the axis, and must not be rendered as 80.",
        count: scans.length,
        servers: scans,
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
