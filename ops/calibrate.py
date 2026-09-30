"""Run the scanner against the gold set and report drift and measured rule tiers.

`03` §9's calibration loop, step 1 and 2: scan every entry at the tree its
audit read, compare to the hand audit's expected ranges (`09` §5: ±5 composite,
±8 per axis), and measure each rule's false-positive rate from the audit's
labels. It REPORTS; it flips nothing. `weights.RULESET_CALIBRATED` and
`COMPOSITE_PUBLISHED` stay deliberate edits, and `tests/test_gold_set.py`
refuses either while fewer than `MIN_RATIFIED_ENTRIES` entries are ratified.

What keeps the report honest:
- An entry is measured at its PINNED COMMIT (`GoldEntry.commit`), never at
  whatever its version resolves to today: a tag can be moved and a branch tip
  always is, and 44% of the published cohort was read at a default branch. A
  scan that read a repository the entry does not pin, or read a commit other
  than the pin, leaves the entry unmeasured — `ops/pin_gold_commits.py`
  recovers the audited commit for an entry drafted before pins existed.
- The official figures — measured tiers and "may be declared" — come from
  RATIFIED entries only. `--include-drafts` adds a separately labelled
  preview; a draft never moves an official number.
- Labels are RECONCILED against what the scanner reports now
  (`goldset.reconcile`): a label whose finding is gone is stale, excluded from
  the rates, and blocks declaring calibration until that entry is re-audited.
  The scan keeps every finding (`evidence_cap=None`) — against the published
  50, a label past the cap read as stale — and a label that still cannot be
  checked (Code Safety unassessed) is unverifiable, never stale.
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
2: the environment is not fit to calibrate, some entry or label could not be
measured (named in the output), or the run itself crashed — never 1, which
would read our failure as drift.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
import urllib.error
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
from mcpwatchman.workers.crawler.registry import (
    REGISTRY_BASE_URL,
    SERVERS_PATH,
    RegistryEntry,
    RegistryUnavailableError,
    parse_entry,
)
from mcpwatchman.workers.scanner.runner import scan_entry
from mcpwatchman.workers.scoring.composite import composite_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_cohort import preflight  # noqa: E402 - the same toolchain check the cohort run uses


def registry_entry(name: str, version: str) -> tuple[RegistryEntry | None, str]:
    """The registry's record for exactly this name and version, or None and why.

    The exact endpoint, not a search. A search pages through every fuzzy match
    and took 31 s a page (measured 2026-09-30), past the read timeout — 16 of 30
    lookups failed that way — and its miss was only as good as the pages read.
    An exact 404 IS an absence; anything else that fails is ours, and raises.
    """
    url = (f"{REGISTRY_BASE_URL}{SERVERS_PATH}/{urllib.parse.quote(name, safe='')}"
           f"/versions/{urllib.parse.quote(version, safe='')}")
    try:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https host
            return parse_entry(json.load(response)), ""
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, "is not in the registry"
        raise


def pin_problem(entry: GoldEntry, report: dict) -> str:
    """Why this scan is not a measurement of the tree the audit read, or "".

    Labels key on (rule, path, line) and the expected ranges describe one tree,
    so a scan of any other tree is not evidence about the rules — its drift and
    stale labels would be the code's movement. Replaces a warning that only
    flagged default-branch reads: an unpinned TAGGED read moves too, whenever
    the tag does.
    """
    read = report.get("repository_commit")
    if entry.commit is None:
        if read is None:
            # No repository commit: a package source (pinned by its version),
            # or a repository that could not be read — an outcome the
            # comparison then judges like any other.
            return ""
        return (f"the scan read a repository (today: {read}) but the entry pins no "
                "commit, so the audited tree is unknown — run ops/pin_gold_commits.py")
    if read != entry.commit:
        return f"pinned {entry.commit}, but the scan read {read or 'no repository'}"
    return ""


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

    # Outcomes hold the ENTRY, never its name: a ratified entry and a draft of
    # the same server can both be loaded, and keyed by name the draft's drift
    # would block the ratified verdict it is barred from moving (Codex leg).
    drifted: list[GoldEntry] = []
    stale_entries: list[GoldEntry] = []
    unmeasured: list[GoldEntry] = []
    unchecked: list[GoldEntry] = []
    official: list[Label] = []
    preview: list[Label] = []
    for entry in entries:
        try:
            found, why = registry_entry(entry.name, entry.version)
        except (OSError, ValueError, RegistryUnavailableError) as exc:
            # Ours (a network or registry outage), so a skip — never drift.
            print(f"[unmeasured] {entry.name}: the registry could not be read — {exc}")
            unmeasured.append(entry)
            continue
        if found is None:
            print(f"[unmeasured] {entry.name}@{entry.version} {why}")
            unmeasured.append(entry)
            continue
        report = scan_entry(found, evidence_cap=None, commit=entry.commit).to_dict()
        ours = unpublishable_gaps(entry.name, report)
        if ours:
            print(f"[unmeasured] {entry.name}: our side failed — {ours[0][:140]}")
            unmeasured.append(entry)
            continue
        unpinned = pin_problem(entry, report)
        if unpinned:
            print(f"[unmeasured] {entry.name}: {unpinned}")
            unmeasured.append(entry)
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
        if rec.unverifiable:
            print(f"          {len(rec.unverifiable)} label(s) could not be checked: "
                  f"{rec.unverifiable_reason}")
        if rec.unlabeled or rec.evidence_omitted:
            print(f"          {len(rec.unlabeled)} current finding(s) unlabelled"
                  + (f", {rec.evidence_omitted} more not shown (evidence cap)"
                     if rec.evidence_omitted else ""))
        if drift:
            drifted.append(entry)
        if rec.stale:
            stale_entries.append(entry)
        if rec.unverifiable:
            unchecked.append(entry)

    _print_tiers("measured tiers — RATIFIED entries only (the official figures):", official)
    if args.include_drafts:
        _print_tiers("PREVIEW — draft labels only, counted toward nothing:", preview)

    blocking = [e for e in drifted + stale_entries + unmeasured + unchecked if e.ratified]
    ready = ratified >= MIN_RATIFIED_ENTRIES and not blocking
    print(
        f"\n{len(drifted)} of {len(entries)} entries drift, {len(stale_entries)} carry stale "
        f"labels, {len(unmeasured)} could not be measured, {len(unchecked)} have labels "
        "that could not be checked. Calibration "
        + ("may be declared." if ready else
           f"may NOT be declared: it needs >= {MIN_RATIFIED_ENTRIES} ratified entries, "
           "every one measured with every label checked, none drifting or stale.")
    )
    if unmeasured or unchecked:
        return 2
    return 1 if (drifted or stale_entries) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - printed in full; only the exit code is chosen
        # An uncaught exception exits 1, and 1 means drift. A crash is ours.
        traceback.print_exc()
        sys.exit(2)
