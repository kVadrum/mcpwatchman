import reports from "./reports";
import apiChanges from "../data/api-changes.json";

/**
 * The full records, in pages: `/api/servers.json` is page 1 and the rest live
 * at `/api/pages/servers/<n>.json` (operator ruling 2026-11-16, announced in
 * `api-changes.json` 30 days ahead). One document of every record passes the
 * host's 25 MiB per-file limit near 2,000 servers; pages keep every file under
 * it while a reader that follows `next` still gets everything in a few
 * requests.
 *
 * `/api/pages/servers/` is its own namespace on purpose: under
 * `/api/servers/` a page URL could collide with a server's slug.
 *
 * `page_size` lives in `api-changes.json` beside the notice that promises it,
 * so the prose and the paging cannot disagree; `tests/test_api_changes.py`
 * holds them together and refuses a published set larger than one page while
 * the change is only announced.
 */
export const PAGE_SIZE: number = apiChanges.page_size;
if (!Number.isInteger(PAGE_SIZE) || PAGE_SIZE < 1) {
  throw new Error(`api-changes.json page_size must be a positive integer, got ${PAGE_SIZE}`);
}

const BASE = "https://mcpwatchman.com";

export const PAGE_COUNT = Math.max(1, Math.ceil(reports.length / PAGE_SIZE));

export const pageUrl = (n: number) =>
  n === 1 ? `${BASE}/api/servers.json` : `${BASE}/api/pages/servers/${n}.json`;

/** Page `n` of the full records, in the order every other surface uses. */
export const page = (n: number) => ({
  count: reports.length,
  page: n,
  page_count: PAGE_COUNT,
  page_size: PAGE_SIZE,
  prev: n > 1 ? pageUrl(n - 1) : null,
  next: n < PAGE_COUNT ? pageUrl(n + 1) : null,
  servers: reports.slice((n - 1) * PAGE_SIZE, n * PAGE_SIZE),
});
