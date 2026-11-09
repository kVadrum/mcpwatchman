"""The published reports: one home for reading them, in either layout.

Operator ruling D2a (2026-11-09): the store moves from one `scans.json` to one
file per server, because at 5,000 servers the monolith is ~64 MB, past GitHub's
50 MB warning, and every nightly commits a rewrite of all of it.

⚠ **THE MOVE IS EXPAND-THEN-CONTRACT, AND THE ORDER IS LOAD-BEARING.** The
nightly runs `main`'s CODE over `dev`'s DATA (`ops/nightly.sh`), so a layout
that reaches `dev` before every reader that will meet it reaches `main` breaks
the night. Every reader accepts both layouts and is synced FIRST; only then may
a writer produce the new one.

Layouts, both named by the monolith path every caller already passes:

    <dir>/scans.json           a JSON list of reports, sorted by name
    <dir>/reports/<slug>.json  one report per file

Exactly one may exist. Both at once is a half-finished move, refused rather
than guessed at: either answer would publish one layout's pages over the
other's without saying so.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

SHARD_DIR = "reports"
# Our own `slugify` output. A file name is built from it, so anything else is
# refused rather than written or read: a slug is not a path.
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
GIT = shutil.which("git") or "git"


class StoreError(ValueError):
    """The store is in a state no reader may guess about."""


def shard_dir(path: Path) -> Path:
    return path.parent / SHARD_DIR


def shard_name(slug: str) -> str:
    if not _SLUG.match(slug):
        raise StoreError(f"not a slug: {slug!r}")
    return f"{slug}.json"


def _ordered(rows: list[Any], where: str) -> list[dict[str, Any]]:
    """Shards in the monolith's own order (`ops/scan_cohort.py` writes it
    sorted by name), so a reader cannot tell which layout it was handed. The
    monolith itself is returned exactly as written: the visibility gate must
    see a malformed row to withhold it, never a reader that rejected it first."""
    if not all(isinstance(r, dict) and isinstance(r.get("name"), str) for r in rows):
        raise StoreError(f"{where} holds something that is not a named report")
    return sorted(rows, key=lambda r: r["name"])


def exists(path: Path) -> bool:
    return path.is_file() or shard_dir(path).is_dir()


def read_reports(path: Path) -> list[dict[str, Any]]:
    """Every published report, sorted by name, from whichever layout is there."""
    shards = shard_dir(path)
    if path.exists() and shards.exists():
        raise StoreError(f"both {path.name} and {SHARD_DIR}/ exist beside it: a "
                         "half-finished move between layouts")
    if path.exists():
        rows = json.loads(path.read_text())
        if not isinstance(rows, list):
            raise StoreError(f"{path.name} is not a list of reports")
        return rows
    if shards.is_dir():
        rows = []
        for f in shards.iterdir():
            if f.suffix != ".json" or not f.is_file() or f.is_symlink():
                raise StoreError(f"{SHARD_DIR}/ holds {f.name!r}, which is not a report")
            row = json.loads(f.read_text())
            if not isinstance(row, dict) or f.name != shard_name(str(row.get("slug"))):
                raise StoreError(f"{SHARD_DIR}/{f.name} does not hold the report its name says")
            rows.append(row)
        return _ordered(rows, f"{SHARD_DIR}/")
    raise FileNotFoundError(path)


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argument list, fixed executable
        [GIT, "-C", str(repo), *args], check=check, capture_output=True, text=True,
    )


def read_reports_at(repo: Path, ref: str, data: str) -> list[dict[str, Any]]:
    """`read_reports` at a git ref: `data` is the monolith's repo-relative path.

    Score history is DERIVED from every data commit (`ops/score_history.py`),
    so after the move one walk crosses commits in both layouts.
    """
    shards = str(PurePosixPath(data).parent / SHARD_DIR)
    mono = _git(repo, "cat-file", "-e", f"{ref}:{data}", check=False).returncode == 0
    split = _git(repo, "cat-file", "-e", f"{ref}:{shards}", check=False).returncode == 0
    if mono and split:
        raise StoreError(f"{ref} holds both {data} and {shards}/")
    if mono:
        rows = json.loads(_git(repo, "show", f"{ref}:{data}").stdout)
        if not isinstance(rows, list):
            raise StoreError(f"{data} at {ref} is not a list of reports")
        return rows
    if split:
        rows = []
        for name, blob in _blobs(repo, f"{ref}:{shards}"):
            row = json.loads(blob)
            if not isinstance(row, dict) or name != shard_name(str(row.get("slug"))):
                raise StoreError(f"{shards}/{name} at {ref} does not hold the report "
                                 "its name says")
            rows.append(row)
        return _ordered(rows, f"{shards}/ at {ref}")
    raise FileNotFoundError(f"{ref}:{data}")


def _blobs(repo: Path, tree: str) -> list[tuple[str, bytes]]:
    """(name, content) of every entry in one tree, read in ONE `cat-file
    --batch`: a `git show` per shard is 5,000 processes per commit, and a
    history rebuild walks every data commit."""
    entries = []
    for line in filter(None, _git(repo, "ls-tree", "-z", tree).stdout.split("\0")):
        meta, name = line.split("\t", 1)
        _mode, kind, oid = meta.split()
        if kind != "blob":
            raise StoreError(f"{tree}/{name} is a {kind}, not a report")
        entries.append((name, oid))
    proc = subprocess.run(  # noqa: S603 - argument list, fixed executable
        [GIT, "-C", str(repo), "cat-file", "--batch"],
        input="".join(f"{oid}\n" for _, oid in entries).encode(),
        check=True, capture_output=True,
    )
    out, at, blobs = proc.stdout, 0, []
    for name, oid in entries:
        end = out.index(b"\n", at)
        got, kind, size = out[at:end].decode().split()
        if got != oid or kind != "blob":
            raise StoreError(f"git returned {got} {kind} for {name}")
        start = end + 1
        blobs.append((name, out[start:start + int(size)]))
        at = start + int(size) + 1
    return blobs


def data_paths(data: str) -> tuple[str, str]:
    """Both layouts' repo-relative paths, for `git log -- …`: a data commit is
    one that touched either."""
    return data, str(PurePosixPath(data).parent / SHARD_DIR)


__all__ = ["SHARD_DIR", "StoreError", "data_paths", "exists", "read_reports",
           "read_reports_at", "shard_dir", "shard_name"]
