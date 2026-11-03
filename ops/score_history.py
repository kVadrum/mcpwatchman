#!/usr/bin/env python3
"""Derive `site/src/data/history.json` from the `scans.json` versions in git.

    score_history.py --repo . --ref origin/dev --out site/src/data/history.json --rebuild
    score_history.py --repo . --ref $DEV_SHA --history IN --scans TONIGHT --out OUT

The first form rebuilds the whole series from every commit on REF that touched
the published data. The second is the nightly's: it starts from IN, merges every
data commit after the one IN was last brought up to (`through`), then tonight's
not-yet-committed scans, so a night that never ran this — or ran it under a
`main` that predated it — is filled from git the next time, not lost.

    score_history.py ... --withhold-contract "ruleset 0.1.3, methodology 0.2.0"

drops every point scored under that contract (the nightly passes `dev`'s under a
contract mismatch, when it deploys `main`'s code and must not publish `dev`'s
scores through the history either — `history.withhold`). The string is the
nightly's own `contract()` output.
History is derived data (`mcpwatchman.history`); a failure here costs the
night's history update, never its scan.

Exit 0 written, 2 refused (unreadable input, a schema it does not know).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcpwatchman import history as h

DATA = "site/src/data/scans.json"
_CONTRACT = re.compile(r"ruleset (\S+), methodology (\S+)")
GIT = shutil.which("git") or "git"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 - argument list
        [GIT, "-C", str(repo), *args], check=True, capture_output=True, text=True,
    ).stdout


def _commits(repo: Path, ref: str, since: str | None) -> list[str]:
    """Data commits on `ref` after `since`, oldest first; all of them if `since`
    is unknown or no longer an ancestor (a rewritten branch)."""
    rng = ref
    if since:
        ok = subprocess.run(  # noqa: S603
            [GIT, "-C", str(repo), "merge-base", "--is-ancestor", since, ref],
            capture_output=True,
        ).returncode == 0
        if ok:
            rng = f"{since}..{ref}"
    out = _git(repo, "log", "--format=%H", "--reverse", rng, "--", DATA)
    return out.split()


def _load_reports(text: str) -> list[dict[str, Any]]:
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError("scans.json is not a list of reports")
    return rows


def dump(history: dict[str, Any]) -> str:
    """One server per line: a night's update is a one-line diff per server."""
    head = {k: v for k, v in history.items() if k not in ("servers", "drops")}
    lines = ["{"]
    for k, v in head.items():
        lines.append(f"{json.dumps(k)}: {json.dumps(v, ensure_ascii=False)},")
    lines.append('"drops": [')
    drops = history["drops"]
    compact = (",", ":")
    lines += [json.dumps(d, ensure_ascii=False, separators=compact)
              + ("," if i < len(drops) - 1 else "")
              for i, d in enumerate(drops)]
    lines.append("],")
    lines.append('"servers": {')
    items = sorted(history["servers"].items())
    lines += [f"{json.dumps(slug)}:{json.dumps(series, ensure_ascii=False, separators=(',', ':'))}"
              + ("," if i < len(items) - 1 else "")
              for i, (slug, series) in enumerate(items)]
    lines.append("}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--history", type=Path, help="the history to update (absent: start empty)")
    ap.add_argument("--scans", type=Path, help="tonight's scans.json, not yet committed")
    ap.add_argument("--withhold-contract", metavar="'ruleset R, methodology M'",
                    help="drop every point scored under this contract")
    a = ap.parse_args(argv)
    withheld_contract = None
    if a.withhold_contract is not None:
        m = _CONTRACT.fullmatch(a.withhold_contract)
        if m is None:
            print(f"score_history: refused: unreadable contract {a.withhold_contract!r}",
                  file=sys.stderr)
            return 2
        withheld_contract = (m.group(2), m.group(1))

    try:
        if a.rebuild or a.history is None or not a.history.exists():
            hist = h.empty()
        else:
            hist = json.loads(a.history.read_text(encoding="utf-8"))
        merged = 0
        latest: list[dict[str, Any]] = []
        commits = _commits(a.repo, a.ref, None if a.rebuild else hist.get("through"))
        for sha in commits:
            latest = _load_reports(_git(a.repo, "show", f"{sha}:{DATA}"))
            merged += h.merge(hist, latest)
        hist["through"] = _git(a.repo, "rev-parse", a.ref).strip()
        if a.scans:
            latest = _load_reports(a.scans.read_text(encoding="utf-8"))
            merged += h.merge(hist, latest)
        elif not latest:
            latest = _load_reports(_git(a.repo, "show", f"{a.ref}:{DATA}"))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"score_history: refused: {exc}", file=sys.stderr)
        return 2

    withheld = h.withhold(hist, *withheld_contract) if withheld_contract else 0
    names = {r["slug"]: r["name"] for r in latest if r.get("slug")}
    today = max((str(r.get("scanned_at", ""))[:10] for r in latest), default="") \
        or datetime.now(UTC).date().isoformat()
    hist["drops"] = h.drops(hist, names, today)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = a.out.with_suffix(".tmp")
    tmp.write_text(dump(hist), encoding="utf-8")
    tmp.replace(a.out)
    points = sum(len(s) for s in hist["servers"].values())
    left_out = (f"; {withheld} point(s) under the withheld contract left out"
                if withheld_contract else "")
    print(f"score_history: {len(commits)} data commit(s) read, "
          f"{merged} point(s) added or updated; {len(hist['servers'])} servers, "
          f"{points} points, {len(hist['drops'])} drop(s) in the window{left_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
