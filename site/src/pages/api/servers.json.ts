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
        ref_note:
          "`ref_matched_version` has three values, not two. true: the tree scanned is the ref the registry entry names. false: no such tag resolved and the default branch was read instead, so the findings describe branch-tip code rather than the named release. null: nothing established it — the source was never fetched, or it came from a package registry where the version is pinned in the URL. null is not false.",
        fault_note:
          "On an axis with `score: null`, `fault` says whose gap it is. `publisher` — a property of what the server published: an unreachable repository, no lockfile, no source in a language the ruleset covers. `project` — a limit of mcpwatchman itself, stated in our own voice: the Maintenance axis reads commit history from the hosting forge and that retrieval is not built, and the methodology defines no band for a vulnerability with no CVSS. Those are the only two values you will see here: a gap caused by our own run — a scanner binary missing, a clone that timed out — is refused at publication rather than printed as the reason a server went unscored, so it never reaches this API.",
        cohort_note:
          "The set of servers here is pinned and append-only: a server that has a page keeps it, its URL does not change, and the set only grows. It is not a random sample of the registry — the servers published first were drawn from the registry's alphabetical head — so do not read it as representative, and never read a server's absence as a judgement. It means we have not published that server.",
        registry_state_note:
          "`registry_state` says what the registry held for this server when the report was published, and it has more than two values. \"listed\": active in the registry, and `registry_note` is empty. The registry's own word for a non-active entry, currently \"deprecated\": the entry is still there, so the server was scanned normally and the label is the publisher's, scored by nothing. \"delisted\": no current entry at all, so the page keeps the last scan taken while the server was listed. \"stale\": still listed, but the most recent run could not measure it, so the page keeps its last successful scan. Every value other than \"listed\" explains itself in `registry_note`; that invariant is the one to code against, because the registry may introduce a status we relay verbatim.",
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
