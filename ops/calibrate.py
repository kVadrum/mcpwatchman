"""Run the scanner against the gold set and report drift and measured rule tiers.

`03` §9's calibration loop, step 1 and 2: scan every entry at its pinned
version, compare to the hand audit's expected ranges (`09` §5: ±5 composite,
±8 per axis), and measure each rule's false-positive rate from the audit's
labels. It REPORTS; it flips nothing. `weights.RULESET_CALIBRATED` and
`COMPOSITE_PUBLISHED` stay deliberate edits, and `tests/test_gold_set.py`
refuses either while fewer than `MIN_RATIFIED_ENTRIES` entries are ratified.

Three things keep the report honest (all from the Codex leg of its /qaa):
- The official figures — measured tiers and "may be declared" — come from
  RATIFIED entries only. `--include-drafts` adds a separately labelled
  preview; a draft never moves an official number.
- Labels are RECONCILED against what the scanner reports now
  (`goldset.reconcile`): a label whose finding is gone is stale, excluded from
  the rates, and blocks declaring calibration until that entry is re-audited.
- A gap of OURS (a missing binary, an exhausted token, a tool over budget)
  is never read as drift — a broken measurement is not evidence about the
  methodology. A missing toolchain refuses the run up front; an our-side gap
  on ONE entry skips that entry by name and blocks declaring calibration,
  but the rest are still measured — aborting the whole run on the first one
  let a single server that fails on our side every night (osv-scanner over
  budget, measured 2026-09-29) block calibration for everyone.

This is a scan: semgrep and osv-scanner on PATH, a GitHub token, network — and
never beside another scan or the test suite (`CLAUDE.md`).

    PATH=.venv-workers/bin:$PATH .venv/bin/python ops/calibrate.py [--include-drafts]

Exit 0: no drift and no stale labels. 1: drift or stale labels, listed.
2: the environment is not fit to calibrate, or some entry could not be
measured (named in the output).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from mcpwatchman.cohort import unpublishable_gaps
from mcpwatchman.goldset import (
    AXES,
    DEFAULT_ROOT,
    MIN_RATIFIED_ENTRIES,
    GoldEntry,
    Label,
    compare,
    entry_files,
    fp_rates,
    load,
    measured_tier,
    reconcile,
)
from mcpwatchman.workers.crawler.registry import REGISTRY_BASE_URL, parse_entry
from mcpwatchman.workers.scanner.runner import scan_entry
from mcpwatchman.workers.scoring.composite import composite_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_cohort import preflight  # noqa: E402 - the same toolchain check the cohort run uses


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


def _print_tiers(title: str, labels: list[Label]) -> None:
    print(f"\n{title}")
    rates = fp_rates(labels)
    if not rates:
        print("  (no reconciled labels)")
    for rule, (fp, total) in sorted(rates.items()):
        print(f"  {rule:48} {fp}/{total} fp -> {measured_tier(fp, total)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument(
        "--include-drafts", action="store_true",
        help="also run drafts, reported as a separate PREVIEW — never counted",
    )
    args = ap.parse_args()

    missing = preflight()
    if missing:
        print("REFUSING TO CALIBRATE:\n  " + "\n  ".join(missing), file=sys.stderr)
        return 2

    files = entry_files(args.root, include_drafts=args.include_drafts)
    entries: list[GoldEntry] = [load(p) for p in files]
    ratified = sum(e.ratified for e in entries)
    print(f"{len(entries)} entries ({ratified} ratified, {len(entries) - ratified} draft)")
    if not entries:
        return 0

    drifted: dict[str, list[str]] = {}
    stale_entries: list[str] = []
    unmeasured: list[str] = []
    official: list[Label] = []
    preview: list[Label] = []
    for entry in entries:
        found = registry_entry(entry.name, entry.version)
        if found is None:
            print(f"[unmeasured] {entry.name}@{entry.version} is not in the registry")
            unmeasured.append(entry.name)
            continue
        report = scan_entry(found).to_dict()
        ours = unpublishable_gaps(entry.name, report)
        if ours:
            print(f"[unmeasured] {entry.name}: our side failed — {ours[0][:140]}")
            unmeasured.append(entry.name)
            continue
        scores = {a: report["axes"][a]["score"] for a in AXES}
        # Computed internally and never written anywhere a surface reads.
        composite = (
            composite_score(scores) if all(v is not None for v in scores.values()) else None
        )
        drift = compare(entry, report, composite)
        rec = reconcile(entry, report)
        (official if entry.ratified else preview).extend(rec.matched)

        tag = "ratified" if entry.ratified else "draft"
        shown = " ".join(f"{a.split('_')[0]}={scores[a]}" for a in AXES)
        status = "drift" if drift or rec.stale else "ok"
        print(f"[{status:5}] {entry.name} ({tag}) {shown} composite={composite}")
        for line in drift:
            print(f"          {line}")
        if rec.stale:
            print(f"          {len(rec.stale)} stale label(s): the scanner no longer reports "
                  "those findings — re-audit this entry")
        if rec.unlabeled or rec.evidence_omitted:
            print(f"          {len(rec.unlabeled)} current finding(s) unlabelled"
                  + (f", {rec.evidence_omitted} more not shown (evidence cap)"
                     if rec.evidence_omitted else ""))
        if drift:
            drifted[entry.name] = drift
        if rec.stale:
            stale_entries.append(entry.name)

    _print_tiers("measured tiers — RATIFIED entries only (the official figures):", official)
    if args.include_drafts:
        _print_tiers("PREVIEW — draft labels only, counted toward nothing:", preview)

    ratified_names = {e.name for e in entries if e.ratified}
    blocking = sorted(ratified_names & (set(drifted) | set(stale_entries) | set(unmeasured)))
    ready = ratified >= MIN_RATIFIED_ENTRIES and not blocking
    print(
        f"\n{len(drifted)} of {len(entries)} entries drift, {len(stale_entries)} carry stale "
        f"labels, {len(unmeasured)} could not be measured. Calibration "
        + ("may be declared." if ready else
           f"may NOT be declared: it needs >= {MIN_RATIFIED_ENTRIES} ratified entries, "
           "every one measured, none drifting or stale.")
    )
    if unmeasured:
        return 2
    return 1 if (drifted or stale_entries) else 0


if __name__ == "__main__":
    sys.exit(main())
