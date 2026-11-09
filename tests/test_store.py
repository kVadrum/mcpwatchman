"""`mcpwatchman.store`: the published reports, read the same from either layout.

The move from one `scans.json` to one file per server (operator ruling D2a,
2026-11-09) is expand-then-contract, because the nightly runs `main`'s code
over `dev`'s data: a reader that cannot tell the layouts apart is what lets
them change underneath it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mcpwatchman import store

ROWS = [
    {"name": "io.github.b/two", "slug": "io-github-b-two", "axes": {}},
    {"name": "com.a/one", "slug": "com-a-one", "axes": {}},
    {"name": "io.github.B/three", "slug": "io-github-b-three", "axes": {}},
]


def _monolith(d: Path, rows=ROWS) -> Path:
    path = d / "scans.json"
    path.write_text(json.dumps(sorted(rows, key=lambda r: r["name"]), indent=1))
    return path


def _shards(d: Path, rows=ROWS) -> Path:
    (d / store.SHARD_DIR).mkdir()
    for r in rows:
        (d / store.SHARD_DIR / store.shard_name(r["slug"])).write_text(json.dumps(r))
    return d / "scans.json"


def test_both_layouts_read_the_same_reports_in_the_same_order(tmp_path: Path) -> None:
    (tmp_path / "m").mkdir()
    (tmp_path / "s").mkdir()
    mono = store.read_reports(_monolith(tmp_path / "m"))
    split = store.read_reports(_shards(tmp_path / "s"))
    assert mono == split
    # The monolith's order: by name, code point, as `scan_cohort` writes it.
    assert [r["name"] for r in split] == ["com.a/one", "io.github.B/three", "io.github.b/two"]


def test_both_layouts_at_once_is_refused(tmp_path: Path) -> None:
    _monolith(tmp_path)
    _shards(tmp_path)
    with pytest.raises(store.StoreError, match="half-finished move"):
        store.read_reports(tmp_path / "scans.json")


def test_neither_layout_is_not_an_empty_store(tmp_path: Path) -> None:
    assert not store.exists(tmp_path / "scans.json")
    with pytest.raises(FileNotFoundError):
        store.read_reports(tmp_path / "scans.json")


@pytest.mark.parametrize("bad", ["../escape", "a/b", "", "UPPER", "-lead", "x.json"])
def test_a_slug_is_never_a_path(bad: str) -> None:
    with pytest.raises(store.StoreError):
        store.shard_name(bad)


def test_a_shard_must_hold_the_report_its_name_says(tmp_path: Path) -> None:
    path = _shards(tmp_path)
    (tmp_path / store.SHARD_DIR / "com-a-one.json").write_text(json.dumps(ROWS[0]))
    with pytest.raises(store.StoreError, match="does not hold the report"):
        store.read_reports(path)


@pytest.mark.parametrize("stray", ["notes.txt", "x.json.bak"])
def test_anything_else_in_the_shard_directory_is_refused(tmp_path: Path, stray: str) -> None:
    path = _shards(tmp_path)
    (tmp_path / store.SHARD_DIR / stray).write_text("{}")
    with pytest.raises(store.StoreError, match="not a report"):
        store.read_reports(path)


def test_a_symlinked_shard_is_refused(tmp_path: Path) -> None:
    path = _shards(tmp_path, ROWS[1:])
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(ROWS[0]))
    (tmp_path / store.SHARD_DIR / "io-github-b-two.json").symlink_to(outside)
    with pytest.raises(store.StoreError, match="not a report"):
        store.read_reports(path)


# --- at a git ref: score history walks commits in both layouts -------------


def _git(repo: Path, *args: str) -> str:
    """Fixed argv over this test's own tmp_path."""
    return subprocess.run(  # noqa: S603
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],  # noqa: S607
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()


DATA = "site/src/data/scans.json"


def test_a_walk_across_the_move_reads_every_commit(tmp_path: Path) -> None:
    data = tmp_path / "site" / "src" / "data"
    data.mkdir(parents=True)
    _git(tmp_path, "init", "-q")
    _monolith(data)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "monolith")
    before = _git(tmp_path, "rev-parse", "HEAD")
    (data / "scans.json").unlink()
    _shards(data)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "shards")
    after = _git(tmp_path, "rev-parse", "HEAD")

    assert store.read_reports_at(tmp_path, before, DATA) == \
        store.read_reports_at(tmp_path, after, DATA) == store.read_reports(data / "scans.json")
    # Both commits are data commits by the paths `git log` is given.
    log = _git(tmp_path, "log", "--format=%H", "--", *store.data_paths(DATA)).split()
    assert log == [after, before]


def test_a_ref_holding_both_layouts_is_refused(tmp_path: Path) -> None:
    data = tmp_path / "site" / "src" / "data"
    data.mkdir(parents=True)
    _git(tmp_path, "init", "-q")
    _monolith(data)
    _shards(data)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "both")
    with pytest.raises(store.StoreError, match="both"):
        store.read_reports_at(tmp_path, "HEAD", DATA)


# --- the site reads through one loader -------------------------------------


SITE_SRC = Path(__file__).resolve().parents[1] / "site" / "src"


def test_no_page_imports_the_monolith_directly() -> None:
    """A static import of a file the move deletes fails the build, and only
    after the flip — so the one loader (`site/src/lib/reports.ts`) is the only
    reader, and a new page that bypasses it is caught here, not on a night."""
    direct = [
        str(p.relative_to(SITE_SRC))
        for p in [*SITE_SRC.rglob("*.astro"), *SITE_SRC.rglob("*.ts")]
        if p.name != "reports.ts" and "data/scans.json" in p.read_text(encoding="utf-8")
    ]
    assert direct == [], f"import from lib/reports instead: {direct}"
    assert "reports.ts" in {p.name for p in (SITE_SRC / "lib").iterdir()}


# --- writing keeps the layout; the flip is one deliberate command ------------


def test_a_writer_keeps_the_layout_it_found_and_the_monolith_bytes(tmp_path: Path) -> None:
    """`scan_cohort` and the visibility gate moved onto `write_reports`; on the
    monolith they must write exactly what they wrote before."""
    (tmp_path / "m").mkdir()
    (tmp_path / "s").mkdir()
    mono, split = _monolith(tmp_path / "m"), _shards(tmp_path / "s")
    rows = store.read_reports(mono)
    store.write_reports(mono, rows)
    assert mono.read_text() == json.dumps(rows, indent=1) + "\n"
    assert store.layout(mono) == store.MONOLITH
    store.write_reports(split, store.read_reports(split))
    assert store.layout(split) == store.SHARDS and not split.exists()


def test_the_split_reads_back_as_the_monolith_it_replaced(tmp_path: Path) -> None:
    path = _monolith(tmp_path)
    before = store.read_reports(path)
    assert store.main(["split", str(path)]) == 0
    assert store.layout(path) == store.SHARDS
    assert store.read_reports(path) == before
    with pytest.raises(store.StoreError, match="not a monolith"):
        store.main(["split", str(path)])


def test_two_reports_with_one_slug_are_refused_as_shards(tmp_path: Path) -> None:
    with pytest.raises(store.StoreError, match="share the slug"):
        store.write_reports(tmp_path / "scans.json", [ROWS[0], dict(ROWS[0], name="x")],
                            layout_=store.SHARDS)


@pytest.mark.parametrize("split", [False, True])
def test_checkout_and_copy_move_either_layout_byte_for_byte(tmp_path: Path, split: bool) -> None:
    """`ops/nightly.sh` moves the data with these; `git show` and `cp` did it
    for the monolith alone, byte for byte, and so must they."""
    repo = tmp_path / "repo"
    data = repo / "site" / "src" / "data"
    data.mkdir(parents=True)
    _git(repo, "init", "-q")
    path = _shards(data) if split else _monolith(data)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "data")
    into = tmp_path / "main"
    (into / "site" / "src" / "data").mkdir(parents=True)
    _monolith(into / "site" / "src" / "data", ROWS[:1])  # main's own, to be replaced
    kind = store.checkout(repo, "HEAD", DATA, into)
    assert kind == (store.SHARDS if split else store.MONOLITH)
    got = into / DATA
    assert store.layout(got) == kind
    assert store.raw_text(got) == store.raw_text(path)
    dst = tmp_path / "dev" / "scans.json"
    dst.parent.mkdir()
    assert store.copy(got, dst) == kind
    assert store.raw_text(dst) == store.raw_text(path)
