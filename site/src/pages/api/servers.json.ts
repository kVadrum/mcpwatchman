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
// Counted rather than asserted: the note below describes the data it ships with.
const legacyAxes = scans.flatMap((r) =>
  Object.values(r.axes).filter((a) => !("unmeasured_faults" in a)),
).length;

// ⚠ ALSO COUNTED, for the same reason. `fault_note` used to state as a
// standing fact that `03` §5's forge retrieval "is not built" — true until it
// was, and then a sentence telling every agent consumer that a whole axis is
// permanently dark while the data beside it carried scores. The example given
// for `project` has to come from the data, not from what was true the day the
// note was written.
const maintenanceScored = scans.filter((r) => r.axes.maintenance?.score !== null).length;

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
          "On an axis with `score: null`, `fault` says whose gap it is. `publisher` — a property of what the server published: an unreachable repository, no lockfile, no source in a language the ruleset covers. `project` — a limit of mcpwatchman itself, stated in our own voice: " +
          (maintenanceScored === 0
            ? "the Maintenance axis reads commit history from the hosting forge and that retrieval is not built, and "
            : "the Maintenance axis queries the GitHub API and does not query other forges, its popularity sub-check needs a registry-wide distribution that is not computed, and ") +
          "the methodology defines no band for a vulnerability with no CVSS. Those are the only two values you will see here: a gap caused by our own run — a scanner binary missing, a clone that timed out — is refused at publication rather than printed as the reason a server went unscored, so it never reaches this API.",
        cohort_note:
          "The set of servers here is pinned and append-only: a server that has a page keeps it, its URL does not change, and the set only grows. It is not a random sample of the registry — the servers published first were drawn from the registry's alphabetical head — so do not read it as representative, and never read a server's absence as a judgement. It means we have not published that server.",
        registry_state_note:
          "`registry_state` says what the registry held for this server when the report was published, and it has more than two values. \"listed\": active in the registry, and `registry_note` is empty. The registry's own word for a non-active entry, currently \"deprecated\": the entry is still there, so the server was scanned normally and the label is the publisher's, scored by nothing. \"delisted\": no current entry at all, so the page keeps the last scan taken while the server was listed. \"stale\": still listed, but the most recent run could not measure it, so the page keeps its last successful scan. Every value other than \"listed\" explains itself in `registry_note`; that invariant is the one to code against, because the registry may introduce a status we relay verbatim.",
        // DERIVED, so the caveat retires itself. `unmeasured_faults` landed
        // after the published set was last generated, so no record carries it
        // today — and a hand-written note saying so would go false, silently,
        // on the first regeneration. That is what an overtaken `do not` cost
        // in `llms.txt`, addressed to the audience least able to notice.
        unmeasured_faults_note:
          (legacyAxes
            ? `WARNING: ${legacyAxes} axes in this response PREDATE this field and omit it entirely. Check \`scanner_version\`. A missing key means unknown, never fully measured. `
            : "") +
          "On an axis that DOES carry a score, `unmeasured_faults` lists whose gap the unmeasured remainder is — the sub-checks that could not be evaluated and were renormalised out before the score was computed. Where present it is empty only when the axis was measured in full, and otherwise names the gap even when that gap is ordinary: `publisher` for a repository we could not read is the common case, not an exception. It never contains a gap caused by our own run — a partly-measured axis whose missing part is our fault is refused at publication exactly as a wholly unmeasured one is, so a scored axis here is never hiding a broken scanner. Read it together with `assessed_weight`, which says how much of the axis the score covers.",
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
