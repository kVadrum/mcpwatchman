#!/usr/bin/env python3
"""Scan a stable sample of the registry and emit the site's data file.

**In the repository rather than a scratch directory, because the published
numbers are not reproducible without it.** Every figure on mcpwatchman.com was
produced by a script that existed only in one session's tmpdir — so "40 servers
sampled" could not be re-derived by anyone, including us.

⚠ **THE SAMPLE MUST BE STABLE ACROSS RUNS, AND SEEDING A SHUFFLE IS NOT ENOUGH.**
The first version did `random.Random(SEED).shuffle(entries)`, which is
reproducible for a FIXED input list and nothing more. The registry grows
between fetches, so the list differs every run and the same seed selects a
different sample: measured, two consecutive regenerations shared **21 of 40**
servers, with 19 replaced. That silently invalidated every score-diff taken
between runs — those comparisons were across partly-different populations while
being reported as if one set had changed.

Ordering by a hash of the server's own NAME fixes it: a server's position
depends only on its identity, so it stays in or out as the registry grows, and
new entries slot in without displacing the existing sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import httpx

from mcpwatchman import __version__
from mcpwatchman.workers.crawler.registry import REGISTRY_BASE_URL, parse_page, resolve_source
from mcpwatchman.workers.scanner.runner import scan_entry

# One page is 100 entries; the pause is `DEFAULT_PAUSE` from the crawl-rate
# measurement, and `CLAUDE.md`'s posture toward the registry is collaborative.
PAGE_PAUSE_S = 1.0


def sample_key(name: str) -> str:
    """Stable ordering key for a server, derived only from its identity."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def fetch_entries(client: httpx.Client, want: int) -> list:
    entries: list = []
    cursor = None
    while len(entries) < want:
        params = {"limit": 100, "version": "latest"}
        if cursor:
            params["cursor"] = cursor
        page = client.get(f"{REGISTRY_BASE_URL}/v0/servers", params=params).json()
        got, cursor = parse_page(page)
        entries.extend(got)
        if not cursor:
            break
        time.sleep(PAGE_PAUSE_S)
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--count", type=int, default=40, help="servers to scan")
    ap.add_argument("--pool", type=int, default=800, help="entries to draw from")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    agent = f"mcpwatchman/{__version__} (+https://mcpwatchman.com)"
    with httpx.Client(timeout=60, headers={"User-Agent": agent}) as client:
        entries = fetch_entries(client, args.pool)
    print(f"registry: {len(entries)} entries fetched", flush=True)

    # Hash order, not a seeded shuffle — see the module docstring.
    entries.sort(key=lambda e: sample_key(e.name))

    reports = []
    started = time.time()
    for entry in entries:
        if len(reports) >= args.count:
            break
        resolution = resolve_source(entry)
        if not (resolution.scannable and resolution.primary):
            continue
        t0 = time.time()
        report = scan_entry(entry)
        reports.append(report)
        axes = " ".join(
            f"{k.split('_')[0]}={'—' if v.score is None else v.score}"
            for k, v in report.axes.items()
        )
        print(f"[{len(reports):2}/{args.count}] {time.time() - t0:5.1f}s "
              f"{report.name[:44]:44} {report.source_state:13} {axes}", flush=True)

    args.out.write_text(json.dumps([r.to_dict() for r in reports], indent=1))
    print(f"\n{len(reports)} servers in {time.time() - started:.0f}s -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
