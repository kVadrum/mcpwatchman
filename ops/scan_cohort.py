#!/usr/bin/env python3
"""Scan the PINNED cohort and emit the site's data file.

**In the repository rather than a scratch directory, because the published
numbers are not reproducible without it.** Every figure on mcpwatchman.com was
once produced by a script that existed only in one session's tmpdir — so
"40 servers sampled" could not be re-derived by anyone, including us.

⚠ **THE SET OF PUBLISHED SERVERS IS AN INPUT NOW, NOT AN OUTCOME.**
`ops/cohort.json` is the authority on which servers have a page; this script
decides only what those pages SAY. That inversion is the fix for a rotation
that shipped: the previous version drew candidates from the first 800 registry
entries and ordered them by `sha256(name)`, and while the hash order is stable,
the registry paginates alphabetically — so the pool was an alphabetical prefix
that every new registration shifted. Two runs two days apart shared 4 of 40,
and 100 servers have had a page and lost it. `mcpwatchman.cohort` carries the
measurements.

Growth is therefore deliberate: `--grow N` adds N servers and writes them back
into the cohort file, in the same run that first publishes them. A plain
regeneration cannot change the set at all, which is what makes the URLs
durable.

**Growth draws from the WHOLE registry in hash order, which also fixes a
sampling bias nobody chose.** The pinned 40 sit at registry positions 12–773
of 33,079 and every one of them is named `ai.*` — an artefact of the
alphabetical pool, not a property of the registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from mcpwatchman.cohort import (
    Cohort,
    carry_forward,
    load,
    mark_status,
    publication_errors,
    save,
)
from mcpwatchman.workers.crawler.registry import (
    RegistryEntry,
    current_entries,
    fetch_all,
    resolve_source,
)
from mcpwatchman.workers.scanner.runner import scan_entry, slugify

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COHORT = REPO_ROOT / "ops" / "cohort.json"


def sample_key(name: str) -> str:
    """Ordering key for GROWTH candidates, derived only from a server's identity.

    Reproducible and unbiased: it does not depend on what else the registry
    holds, so two people growing the cohort by 10 pick the same 10. It is no
    longer load-bearing for stability — the cohort file is — and that is the
    point: this decides what to ADD, never what to keep.
    """
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _scan(entry: RegistryEntry, label: str, index: int, total: int) -> dict:
    t0 = time.time()
    report = scan_entry(entry)
    axes = " ".join(
        f"{k.split('_')[0]}={'—' if v.score is None else v.score}"
        for k, v in report.axes.items()
    )
    print(
        f"[{index:3}/{total}] {label:9} {time.time() - t0:5.1f}s "
        f"{report.name[:40]:40} {report.source_state:13} {axes}",
        flush=True,
    )
    return report.to_dict()


def _growth_candidates(
    live: dict[str, RegistryEntry], pinned: frozenset[str]
) -> list[RegistryEntry]:
    """Unpinned, scannable entries in hash order.

    The scannability filter is inherited deliberately rather than by accident,
    and it is the one place this script narrows what gets published: a
    remote-only server declares nothing to fetch, so it can only ever produce a
    non-assessment page. `CLAUDE.md`'s end state is that those servers get a
    page too — that is a product decision about what the published set MEANS,
    and it belongs to whoever grows the cohort, not to a default in here.
    """
    unpinned = [e for name, e in live.items() if name not in pinned]
    unpinned.sort(key=lambda e: sample_key(e.name))
    out = []
    for entry in unpinned:
        resolution = resolve_source(entry)
        if resolution.scannable and resolution.primary:
            out.append(entry)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True, help="site data file to write")
    ap.add_argument("--cohort", type=Path, default=DEFAULT_COHORT)
    ap.add_argument(
        "--grow",
        type=int,
        default=0,
        metavar="N",
        help="also publish N servers not yet in the cohort, and pin them",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan — what would be scanned, grown, carried forward",
    )
    args = ap.parse_args()

    cohort = load(args.cohort)
    print(f"cohort: {len(cohort)} servers pinned ({args.cohort})", flush=True)

    # `fetch_all` refuses to return a partial manifest, which is what licenses
    # the conclusion below that a pinned server is ABSENT rather than merely
    # unfetched. The old 800-entry pool could not tell those apart, and read
    # "outside my window" as "not in the registry".
    started = time.time()
    manifest = fetch_all()
    live = {e.name: e for e in current_entries(manifest)}
    listed = {e.name: e for e in manifest}
    print(
        f"registry: {len(manifest)} entries, {len(live)} active-latest "
        f"({time.time() - started:.0f}s)",
        flush=True,
    )

    previous: dict[str, dict] = {}
    if args.out.is_file():
        previous = {r["name"]: r for r in json.loads(args.out.read_text())}

    today = time.strftime("%Y-%m-%d", time.gmtime())
    to_scan: list[RegistryEntry] = []
    # Scannable, but the registry's status is not `active` — the entry is real,
    # so the numbers can be current and the status is relayed beside them.
    to_flag: list[RegistryEntry] = []
    to_carry: list[tuple[str, str]] = []
    for pin in cohort.servers:
        if pin.name in live:
            to_scan.append(live[pin.name])
            continue
        entry = listed.get(pin.name)
        if entry is not None and entry.is_latest:
            # Present, latest, not active: deprecated (349 of 33,081 entries
            # on 2026-09-18). Its source still resolves, so scan it.
            to_flag.append(entry)
            continue
        # Absent, or present only as a SUPERSEDED version — `current_entries`
        # exists because scoring one publishes a grade against code nobody
        # installs. Either way there is no current entry to scan, so the page
        # keeps the last scan taken while the server was listed.
        observation = (
            f"The registry lists this server only at version {entry.version}, "
            "which is no longer the latest"
            if entry is not None
            else "The registry no longer lists this server"
        )
        to_carry.append((pin.name, observation))

    missing_history = [name for name, _ in to_carry if name not in previous]
    if missing_history:
        # Refusing here rather than dropping them: a pinned server with no
        # prior report and no registry entry cannot be published at all, and
        # writing the file anyway would 404 a live URL silently — the exact
        # failure the pin exists to prevent.
        print(
            "REFUSING TO WRITE: these pinned servers are not in the registry "
            "and have no previous report to carry forward, so their pages "
            "cannot be published:\n  " + "\n  ".join(missing_history),
            file=sys.stderr,
        )
        return 2

    growth: list[RegistryEntry] = []
    if args.grow > 0:
        growth = _growth_candidates(live, cohort.names)[: args.grow]
        if len(growth) < args.grow:
            print(
                f"only {len(growth)} scannable unpinned servers available",
                file=sys.stderr,
            )

    if args.dry_run:
        print(f"\nwould scan   {len(to_scan)} pinned")
        print(f"would scan   {len(to_flag)} pinned, flagged with a non-active status")
        for entry in to_flag:
            print(f"   {entry.name} — status {entry.status}")
        print(f"would carry  {len(to_carry)} pinned (no current registry entry)")
        for name, observation in to_carry:
            print(f"   {name} — {observation}")
        print(f"would grow   {len(growth)}")
        for entry in growth:
            print(f"   {entry.name} -> /servers/{slugify(entry.name)}/")
        return 0

    total = len(to_scan) + len(to_flag) + len(growth)
    reports: dict[str, dict] = {}
    index = 0
    for entry in to_scan:
        index += 1
        reports[entry.name] = _scan(entry, "pinned", index, total)
    for entry in to_flag:
        index += 1
        reports[entry.name] = mark_status(
            _scan(entry, "flagged", index, total),
            status=entry.status,
            observed_on=today,
        )
    for entry in growth:
        index += 1
        reports[entry.name] = _scan(entry, "new", index, total)
    for name, observation in to_carry:
        reports[name] = carry_forward(
            previous[name], checked_on=today, observation=observation
        )
        print(f"[carried] {name} — {observation}", flush=True)

    grown: Cohort = cohort
    if growth:
        grown = cohort.extended_with((e.name for e in growth), on=today)

    # The decision to refuse lives in `cohort.publication_errors`, which is
    # where it can be tested: every case it names is invisible once written.
    problems = publication_errors(grown, reports.values())
    if problems:
        print(
            "REFUSING TO WRITE:\n  " + "\n  ".join(problems),
            file=sys.stderr,
        )
        return 2

    ordered = [reports[pin.name] for pin in grown.servers]
    args.out.write_text(json.dumps(ordered, indent=1) + "\n")
    if growth:
        save(args.cohort, grown)
        print(f"cohort grown to {len(grown)} — commit {args.cohort.name}")
    print(
        f"\n{len(ordered)} servers -> {args.out} "
        f"({len(to_scan) + len(to_flag)} scanned, {len(growth)} new, "
        f"{len(to_carry)} carried) "
        f"in {time.time() - started:.0f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
