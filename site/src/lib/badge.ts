/**
 * The README badge (`06` §2), pre-rendered at build as a static SVG.
 *
 * ⚠ `06` §2 specifies the badge as "the current composite score and color".
 * The composite is computed and WITHHELD until gold-set calibration
 * (`weights.composite_published()`), so a badge printing it would publish the
 * one number this project refuses to publish — in other people's READMEs,
 * where it cannot be corrected. `06` §1.2 already names the fallback: "badges
 * display the per-axis minimum score instead — the most conservative
 * summary". So the right half is the LOWEST scored axis, NAMED: a bare number
 * would read as an overall score whatever we meant by it.
 *
 * A score never travels without its coverage (`CLAUDE.md`), so a partly
 * measured axis carries its measured share on the badge itself, rounded DOWN
 * like every coverage claim. Every axis, scored or not, is in the `<title>`.
 *
 * Static, script-free, style-free SVG: the CSP on `/*` is `default-src 'none'`
 * with no `unsafe-inline`, and a README renders it through an image proxy
 * anyway. No external font — `textLength` pins each run to the width computed
 * here, so a fallback face cannot overflow its box.
 */
import { AXES, M } from "./methodology";

// `06` §2: green ≥ 80, yellow 60–79, orange 40–59, red < 40 — the same bands
// as `03` §8's colour derivation, held in `methodology.json` and checked
// against `composite.color()` by tests/test_site_methodology.py.
const bandMin = (name: string): number => {
  const band = M.color_bands.find((b) => b.name === name);
  if (!band) throw new Error(`no colour band ${name}`);
  return band.min;
};
export const BADGE_GREEN_MIN = bandMin("green");
export const BADGE_YELLOW_MIN = bandMin("yellow");
export const BADGE_ORANGE_MIN = bandMin("orange");

export type BadgeColour = "green" | "yellow" | "orange" | "red" | "grey";

// Each pair measured at ≥ 4.5:1 (WCAG AA for 11px text); the built badges
// are re-measured by the test suite, so a palette edit cannot quietly fail.
const PALETTE: Record<BadgeColour | "label", { fill: string; ink: string }> = {
  label: { fill: "#1a222c", ink: "#e7ecf3" },
  green: { fill: "#1d7a3a", ink: "#ffffff" },
  yellow: { fill: "#e9b949", ink: "#1a1204" },
  orange: { fill: "#b4520f", ink: "#ffffff" },
  red: { fill: "#b3261e", ink: "#ffffff" },
  grey: { fill: "#5d6a7a", ink: "#ffffff" },
};

export const colourFor = (score: number): BadgeColour =>
  score >= BADGE_GREEN_MIN
    ? "green"
    : score >= BADGE_YELLOW_MIN
      ? "yellow"
      : score >= BADGE_ORANGE_MIN
        ? "orange"
        : "red";

/** Measured share as a whole percent, rounded DOWN, from the decimal string. */
export const measuredPercent = (assessedWeight: string): number =>
  Math.floor(Math.round(Number(assessedWeight) * 1e6) / 1e4);

interface AxisResult {
  score: number | null;
  assessed_weight: string;
}
interface BadgeReport {
  name: string;
  slug: string;
  scanned_at: string;
  registry_state: string;
  axes: Record<string, AxisResult>;
}

export interface Badge {
  value: string;
  colour: BadgeColour;
  title: string;
}

export function badgeFor(report: BadgeReport): Badge {
  const lines = AXES.map((axis) => {
    const a = report.axes[axis.key];
    return a.score === null
      ? `${axis.label}: not assessed`
      : `${axis.label}: ${a.score} (${measuredPercent(a.assessed_weight)}% measured)`;
  });
  const scored = AXES.filter((axis) => report.axes[axis.key].score !== null);
  // First in AXES order wins a tie, so the choice is deterministic.
  const lowest = scored.reduce<(typeof AXES)[number] | null>(
    (worst, axis) =>
      worst === null || (report.axes[axis.key].score as number) < (report.axes[worst.key].score as number)
        ? axis
        : worst,
    null,
  );

  let value: string;
  let colour: BadgeColour;
  let lead: string;
  if (report.registry_state === "delisted") {
    // STATE: a server the registry no longer lists must not keep a LIVE
    // badge. Its page keeps the last scan, labelled; the badge says why.
    value = "delisted";
    colour = "grey";
    lead = `${report.name} is no longer listed in the official MCP registry; its page keeps the last scan taken while it was.`;
  } else if (lowest === null) {
    value = "not scored";
    colour = "grey";
    lead = `No axis of ${report.name} could be assessed; its page says what was not evaluated and why.`;
  } else {
    const a = report.axes[lowest.key];
    const pct = measuredPercent(a.assessed_weight);
    value = `${lowest.label.toLowerCase()} ${a.score}` + (pct < 100 ? ` (${pct}% measured)` : "");
    colour = colourFor(a.score as number);
    lead = `Lowest scored axis of ${report.name}: ${lowest.label} ${a.score}.`;
  }
  const title =
    `mcpwatchman — ${lead} ` +
    `Per-axis scores, scanned ${report.scanned_at.slice(0, 10)}: ${lines.join("; ")}. ` +
    "No composite score is published until a hand-audited gold set validates the weights.";
  return { value, colour, title };
}

// Approximate advance widths of Verdana at 11px, the face shields.io badges
// are set in. Only used to size the boxes; `textLength` makes the text fit
// them exactly in whatever face renders.
const WIDTHS: Record<string, number> = {
  " ": 3.9, "(": 4.9, ")": 4.9, "%": 11.9, ".": 3.9, "-": 4.9,
  a: 6.7, b: 6.8, c: 5.8, d: 6.8, e: 6.6, f: 3.8, g: 6.8, h: 7.0, i: 3.0,
  j: 3.7, k: 6.4, l: 3.0, m: 10.7, n: 7.0, o: 6.7, p: 6.8, q: 6.8, r: 4.7,
  s: 5.7, t: 4.3, u: 7.0, v: 6.4, w: 9.0, x: 6.4, y: 6.4, z: 5.7,
};
const textWidth = (text: string): number =>
  [...text].reduce((sum, ch) => sum + (WIDTHS[ch] ?? (/\d/.test(ch) ? 7.0 : 7.5)), 0);

const escapeXml = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const PAD = 6;
const LABEL = "mcpwatchman";

export function renderBadge(badge: Badge): string {
  const lw = Math.round(textWidth(LABEL) + PAD * 2);
  const vw = Math.round(textWidth(badge.value) + PAD * 2);
  const w = lw + vw;
  const left = PALETTE.label;
  const right = PALETTE[badge.colour];
  const aria = escapeXml(`${LABEL}: ${badge.value}`);
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" viewBox="0 0 ${w} 20" role="img" aria-label="${aria}">` +
    `<title>${escapeXml(badge.title)}</title>` +
    `<clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>` +
    `<g clip-path="url(#r)">` +
    `<rect width="${lw}" height="20" fill="${left.fill}"/>` +
    `<rect x="${lw}" width="${vw}" height="20" fill="${right.fill}" data-colour="${badge.colour}"/>` +
    `</g>` +
    `<g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="${lw / 2}" y="14" fill="${left.ink}" textLength="${lw - PAD * 2}">${LABEL}</text>` +
    `<text x="${lw + vw / 2}" y="14" fill="${right.ink}" textLength="${vw - PAD * 2}">${escapeXml(badge.value)}</text>` +
    `</g></svg>\n`
  );
}
