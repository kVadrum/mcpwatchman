/**
 * Typed access to the methodology constants in `methodology.json`.
 *
 * The JSON is the one place the site holds a weight, a deduction or a band;
 * `tests/test_site_methodology.py` compares every value to the Python engine.
 * Pages read from here and never type a number themselves — a weight typed
 * into a page is a weight that goes stale the next time calibration moves it,
 * with nothing failing.
 */
import methodology from "./methodology.json";

export type AxisKey =
  | "code_safety"
  | "auth_posture"
  | "dependency_health"
  | "maintenance"
  | "transparency";

export interface Axis {
  key: AxisKey;
  label: string;
  slug: string;
  weight: string;
  scored_by: string;
}

export const M = methodology;
export const AXES = methodology.axes as Axis[];
export const METHODOLOGY_VERSION = methodology.methodology_version;
export const EVIDENCE_CAP = methodology.evidence_cap_per_axis;

export const axisBySlug = (slug: string): Axis => {
  const axis = AXES.find((a) => a.slug === slug);
  if (!axis) throw new Error(`no axis with slug ${slug}`);
  return axis;
};

export const axisByKey = (key: string): Axis => {
  const axis = AXES.find((a) => a.key === key);
  if (!axis) throw new Error(`no axis with key ${key}`);
  return axis;
};

/** "0.30" -> "30". Exact for two-place decimals; no float arithmetic. */
export const percent = (weight: string): string => {
  const [whole, frac = ""] = weight.split(".");
  const hundredths = Number(whole) * 100 + Number((frac + "00").slice(0, 2));
  return String(hundredths);
};

export const subchecks = (key: AxisKey) =>
  (methodology.subcheck_weights as Record<string, { key: string; label: string; weight: string }[]>)[key] ?? [];

/** The stacking ladder as printed percentages: ["100", "75", "50", "25"], then the tail. */
export const stackingPercents = methodology.stacking.map(percent);
export const stackingTailPercent = percent(methodology.stacking_tail);
