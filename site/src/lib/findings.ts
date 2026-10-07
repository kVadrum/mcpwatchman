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

// FNV-1a over the raw key. The readable part lowercases and folds punctuation,
// so `src/a_b.ts` and `src/a-b.ts` (or two paths differing in case) collapsed
// to one id and the feed landed on the wrong finding; the hash keeps them apart.
function fnv1a(text: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36);
}

export function findingAnchor(axis: string, item: FindingLike): string | undefined {
  if (!item.finding) return undefined;
  const raw = `${axis}-${item.finding}-${item.path ?? ""}-${item.line ?? 0}`;
  const readable = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return `finding-${readable}-${fnv1a(raw)}`;
}
