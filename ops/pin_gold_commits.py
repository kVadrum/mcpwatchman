#!/usr/bin/env python3
"""Recover the repository commit a gold-set audit read, for entries drafted
before `commit` existed in the format.

A gold entry pins the tree its audit read (`goldset` — a tag can be moved and a
branch tip always is), and calibration measures only at that pin. The 30 drafts
of 2026-09-29 predate the field (their labels match the 09-21 data, d182c42,
378 of 378 — not the 09-29 regeneration, 338), and no report then recorded a commit, so the
pin has to be RECOVERED from the scan the audit drew its labels from:

- the scan matched a version tag → that tag's commit, as the forge holds it
  today (a tag moved since would show here as a different tree — confirm);
- the scan read a default branch → the last first-parent commit on that branch
  committed before the scan's `scanned_at` (committer date: a commit made
  earlier but pushed later would be picked wrongly — confirm);
- the scan read no repository (a package source) → no pin is needed.

Every recovered pin is a PROPOSAL: `--write` adds it with a comment saying so,
and the human ratifying the entry confirms it against the audit. The data the
audits read is named explicitly (`--data-ref`), never guessed from dates.

    .venv/bin/python ops/pin_gold_commits.py --data-ref d182c42 [--write]

Exit 0: every entry is pinned or needs no pin. 1: some could not be recovered
(named). Network: the registry, and each forge (ls-remote, a commits-only clone).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from mcpwatchman.goldset import DEFAULT_ROOT, GoldEntry, entry_files, load, parse
from mcpwatchman.workers.bounded import run_bounded
from mcpwatchman.workers.commits import valid_commit
from mcpwatchman.workers.crawler.registry import SourceKind, resolve_source
from mcpwatchman.workers.scanner.source import FETCH_TIMEOUT_S, SourceSpec, _git_url

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibrate import registry_entry  # noqa: E402 - the same registry lookup calibration uses

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = "site/src/data/scans.json"


@dataclass(frozen=True)
class RepositoryRead:
    """Which repository a published scan read, and whether a tag matched."""

    spec: SourceSpec
    tag_matched: bool


def repository_read(
    row: dict, primary: str | None, supplement: str | None
) -> RepositoryRead | None:
    """The repository a scan read, from its published row — or None for none.

    The primary source when it is a repository; otherwise the declared
    repository Code Safety fell back to — scored there (the reason names the
    version on a tag match, the default branch otherwise) or found to hold no
    covered source either. Raises when the row shows a repository was read but
    not at which ref: a guessed tree is worse than no pin, because calibration
    would then measure the rules against code nobody audited.
    """
    if primary:
        spec = SourceSpec.parse(primary)
        if spec.kind in (SourceKind.GITHUB, SourceKind.GITLAB):
            matched = row.get("ref_matched_version")
            if matched is None:
                raise RuntimeError("the row does not say whether a tag matched — pin by hand")
            return RepositoryRead(spec, matched is True)
    reason = (row["axes"]["code_safety"].get("reason") or "")
    if supplement and reason.startswith("scored on the declared repository"):
        return RepositoryRead(SourceSpec.parse(supplement), " at version " in reason)
    if supplement and "the declared repository holds no source in a covered language" in reason:
        raise RuntimeError("the declared repository was read, but the row does not say at "
                           "which ref — pin by hand")
    return None


def tag_commit(ls_remote: str, version: str) -> str | None:
    """The commit a version tag names, from `git ls-remote` output.

    Candidates in the fetcher's order (`1.2.3`, then `v1.2.3`); an annotated
    tag's peeled line (`^{}`) is the commit, a lightweight tag's own line is.
    """
    refs: dict[str, str] = {}
    for line in ls_remote.splitlines():
        name, _, ref = line.partition("\t")
        refs[ref.strip()] = name.strip()
    for tag in (version, f"v{version}"):
        found = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
        if found and valid_commit(found):
            return found
    return None


def _git(args: list[str], cwd: Path | None = None) -> str:
    proc = run_bounded(["git", *args], timeout=FETCH_TIMEOUT_S, cwd=cwd)
    if proc.timed_out or proc.returncode != 0:
        tail = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()[-1:] or [""]
        raise RuntimeError(f"git {args[0]} failed: {tail[0][:160]}")
    return proc.stdout or ""


def recover(read: RepositoryRead, scanned_at: str) -> tuple[str, str]:
    """(commit, how) for the tree the scan read. Raises when it cannot say."""
    url = _git_url(read.spec)
    if read.tag_matched:
        tags = [f"refs/tags/{t}{peel}" for t in (read.spec.version, f"v{read.spec.version}")
                for peel in ("", "^{}")]
        sha = tag_commit(_git(["ls-remote", "--", url, *tags]), read.spec.version)
        if sha is None:
            raise RuntimeError(f"the scan matched tag {read.spec.version}, which the forge "
                               "no longer holds — re-audit at a current tree")
        return sha, f"tag {read.spec.version} as the forge holds it today"
    with tempfile.TemporaryDirectory(prefix="mcpw-pin-") as tmp:
        bare = Path(tmp) / "r.git"
        # Commits only, no trees or blobs: the question is which commit, not what is in it.
        _git(["clone", "-q", "--bare", "--filter=tree:0", "--single-branch", "--", url, str(bare)])
        sha = _git(["rev-list", "-1", "--first-parent", f"--before={scanned_at}", "HEAD"],
                   cwd=bare).strip()
    if not valid_commit(sha):
        raise RuntimeError(f"no default-branch commit before {scanned_at}")
    return sha, f"default branch, last commit before the scan at {scanned_at}"


def insert_commit(text: str, commit: str, how: str) -> str:
    """The entry text with `commit = ...` after its `version` line (front matter)."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "+++":
            break
        if line.startswith("version"):
            pin = f'commit = "{commit}"  # recovered ({how}); confirm at ratification\n'
            return "".join(lines[: i + 1] + [pin] + lines[i + 1 :])
    raise ValueError("no `version` line in the front matter")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-ref", required=True,
                    help="git ref of the scans.json the audits drew their labels from")
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--write", action="store_true", help="add the recovered pins to the entries")
    args = ap.parse_args()

    blob = subprocess.run(  # noqa: S603 - argument list, never a shell string
        ["git", "show", f"{args.data_ref}:{DATA}"],  # noqa: S607
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    data = json.loads(blob)
    rows = {r["name"]: r for r in (data if isinstance(data, list) else data["servers"])}

    failed = 0
    for path in entry_files(args.root, include_drafts=True):
        entry: GoldEntry = load(path)
        if entry.commit:
            continue
        row = rows.get(entry.name)
        if row is None or row.get("version") != entry.version:
            print(f"[skip]   {entry.name}@{entry.version}: not in the data at {args.data_ref}")
            failed += 1
            continue
        # Each stage says its name on failure: a bare "read operation timed
        # out" did not say whether the registry or a forge had stalled.
        stage = "registry lookup"
        try:
            found, why = registry_entry(entry.name, entry.version)
            if found is None:
                raise RuntimeError(f"{entry.name}@{entry.version} {why}")
            resolution = resolve_source(found)
            stage = f"the published row at {args.data_ref}"
            read = repository_read(row, resolution.primary, resolution.supplement)
            if read is None:
                print(f"[none]   {entry.name}: the scan read no repository — no pin needed")
                continue
            stage = f"forge ({read.spec})"
            commit, how = recover(read, row["scanned_at"])
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"[failed] {entry.name}: {stage}: {exc}", flush=True)
            failed += 1
            continue
        print(f"[pin]    {entry.name}: {commit} — {how}", flush=True)
        if args.write:
            # Parsed BEFORE it is written: a draft is gitignored and this is its
            # only copy, so a bad insertion must never reach the disk.
            try:
                text = insert_commit(path.read_text(encoding="utf-8"), commit, how)
                if parse(text, source=path.name).commit != commit:
                    raise ValueError("the inserted pin did not parse back")
            except ValueError as exc:
                print(f"[failed] {entry.name}: writing the pin: {exc}", flush=True)
                failed += 1
                continue
            path.write_text(text, encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
