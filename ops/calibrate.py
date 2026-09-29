"""Run the scanner against the gold set and report drift and measured rule tiers.

`03` §9's calibration loop, step 1 and 2: scan every entry at its pinned
version, compare to the hand audit's expected ranges (`09` §5: ±5 composite,
±8 per axis), and measure each rule's false-positive rate from the audit's
labels. It REPORTS; it flips nothing. `weights.RULESET_CALIBRATED` and
`COMPOSITE_PUBLISHED` stay deliberate edits, and `tests/test_gold_set.py`
refuses either while fewer than `MIN_RATIFIED_ENTRIES` entries are ratified.

This is a scan: semgrep and osv-scanner on PATH, a GitHub token, network — and
never beside another scan or the test suite (`CLAUDE.md`).

    PATH=.venv-workers/bin:$PATH .venv/bin/python ops/calibrate.py [--include-drafts]

Exit 0: no drift. 1: drift, listed. 2: an entry could not be scanned.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from mcpwatchman.goldset import (
    AXES,
    DEFAULT_ROOT,
    MIN_RATIFIED_ENTRIES,
    GoldEntry,
    compare,
    entry_files,
    fp_rates,
    load,
    measured_tier,
)
from mcpwatchman.workers.crawler.registry import REGISTRY_BASE_URL, parse_entry
from mcpwatchman.workers.scanner.runner import scan_entry
from mcpwatchman.workers.scoring.composite import composite_score


def registry_entry(name: str, version: str):
    """The registry's record for exactly this name and version, or None."""
    query = urllib.parse.quote(name)
    url = f"{REGISTRY_BASE_URL}/v0/servers?search={query}&limit=100"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https host
        data = json.load(response)
    for item in data.get("servers", []):
        raw = item.get("server", item)
        if raw.get("name") == name and raw.get("version") == version:
            return parse_entry(item)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument(
        "--include-drafts", action="store_true",
        help="also run drafts — for iterating on audits; never counts as calibration",
    )
    args = ap.parse_args()

    files = entry_files(args.root, include_drafts=args.include_drafts)
    entries: list[GoldEntry] = [load(p) for p in files]
    ratified = sum(e.ratified for e in entries)
    print(f"{len(entries)} entries ({ratified} ratified, {len(entries) - ratified} draft)")
    if not entries:
        return 0

    drifted: dict[str, list[str]] = {}
    for entry in entries:
        found = registry_entry(entry.name, entry.version)
        if found is None:
            print(f"[missing] {entry.name}@{entry.version} is not in the registry", file=sys.stderr)
            return 2
        report = scan_entry(found).to_dict()
        scores = {a: report["axes"][a]["score"] for a in AXES}
        # Computed internally and never written anywhere a surface reads.
        composite = (
            composite_score(scores) if all(v is not None for v in scores.values()) else None
        )
        drift = compare(entry, report, composite)
        tag = "ratified" if entry.ratified else "draft"
        shown = " ".join(f"{a.split('_')[0]}={scores[a]}" for a in AXES)
        status = "drift" if drift else "ok"
        print(f"[{status:5}] {entry.name} ({tag}) {shown} composite={composite}")
        for line in drift:
            print(f"          {line}")
        if drift:
            drifted[entry.name] = drift

    print("\nper-rule false-positive rates (from audit labels):")
    for rule, (fp, total) in sorted(fp_rates(entries).items()):
        print(f"  {rule:48} {fp}/{total} fp -> {measured_tier(fp, total)}")

    ready = ratified >= MIN_RATIFIED_ENTRIES and not drifted
    print(
        f"\n{len(drifted)} of {len(entries)} entries drift. Calibration "
        + ("may be declared." if ready else
           f"may NOT be declared: it needs >= {MIN_RATIFIED_ENTRIES} ratified entries "
           "and no drift.")
    )
    return 1 if drifted else 0


if __name__ == "__main__":
    sys.exit(main())
