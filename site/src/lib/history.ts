import history from "../data/history.json";
import scans from "../data/scans.json";

/**
 * Score history, read from `history.json` — derived from the committed data by
 * `mcpwatchman.history`, whose `expand` is the canonical published shape and
 * whose docstring is canonical for what a point means.
 *
 * ⚠ A point is a SCAN. A night that kept a page measured nothing, so it adds
 * no point: a gap in the series is a night we did not measure, and the chart
 * draws it as a gap, never a line across it.
 *
 * ⚠ The committed history may LAG the data (until `main` carries the
 * derivation, the nightly commits scans without it), never lead it. So the
 * page's own current scan is appended here when the history has not caught up
 * — the page and its history then always end on the same scan.
 */

export type AxisPoint = { score: number | null; assessed_weight: string; fault: string | null };
export type HistoryPoint = {
  date: string;
  scanned_at: string;
  methodology_version: string | null;
  ruleset_version: string | null;
  scanner_version: string | null;
  axes: Record<string, AxisPoint>;
};
export type Drop = {
  slug: string;
  name: string;
  axis: string;
  date: string;
  scanned_at: string;
  before: number;
  after: number;
  assessed_weight: string;
  previous_scanned_at: string;
};

type Compact = [string, string | null, string | null, string | null, ...[number | null, string, string | null][]];
type Report = (typeof scans)[number];

const AXES: string[] = history.axes;
const SERIES = history.servers as unknown as Record<string, Compact[]>;

const expand = (p: Compact): HistoryPoint => ({
  date: p[0].slice(0, 10),
  scanned_at: p[0],
  methodology_version: p[1],
  ruleset_version: p[2],
  scanner_version: p[3],
  axes: Object.fromEntries(
    AXES.map((key, i) => {
      const cell = p[4 + i] as [number | null, string, string | null];
      return [key, { score: cell[0], assessed_weight: cell[1], fault: cell[2] }];
    }),
  ),
});

const fromReport = (r: Report): HistoryPoint => ({
  date: r.scanned_at.slice(0, 10),
  scanned_at: r.scanned_at,
  methodology_version: r.methodology_version ?? null,
  ruleset_version: r.ruleset_version ?? null,
  scanner_version: r.scanner_version ?? null,
  axes: Object.fromEntries(
    AXES.map((key) => {
      const a = (r.axes as Record<string, { score: number | null; assessed_weight: string; fault?: string | null }>)[key];
      return [key, { score: a?.score ?? null, assessed_weight: String(a?.assessed_weight ?? "0"), fault: a?.fault ?? null }];
    }),
  ),
});

/** Every recorded scan of one server, oldest first, ending on the page's own scan. */
export function seriesFor(report: Report): HistoryPoint[] {
  const points = (SERIES[report.slug] ?? []).map(expand);
  const last = points.at(-1);
  if (!last || last.scanned_at < report.scanned_at) {
    // Same-day rescan: the latest scan of a day wins (`05` §3.7).
    if (last && last.date === report.scanned_at.slice(0, 10)) points.pop();
    points.push(fromReport(report));
  }
  return points;
}

/** Scores across a contract change are different measurements: a reader marks the seam. */
export const sameContract = (a: HistoryPoint, b: HistoryPoint) =>
  a.methodology_version === b.methodology_version && a.ruleset_version === b.ruleset_version;

export const drops: Drop[] = history.drops as Drop[];
export const historyAxes = AXES;
