/**
 * The anchor a finding lives at on its server page — ONE home, because the
 * high-severity feed links to it and the page renders it, and an anchor
 * computed twice is a link that silently lands at the top of the page the day
 * the two copies disagree.
 *
 * Only a FINDING has one (a rule hit or a vulnerability, `finding` set at
 * scan time); a sub-check's prose has nothing to link to.
 */
export type FindingLike = {
  finding?: string;
  path?: string;
  line?: number;
};

export function findingAnchor(axis: string, item: FindingLike): string | undefined {
  if (!item.finding) return undefined;
  const raw = `${axis}-${item.finding}-${item.path ?? ""}-${item.line ?? 0}`;
  return (
    "finding-" +
    raw
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
  );
}
