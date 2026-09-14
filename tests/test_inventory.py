"""File enumeration invariants (`04-scanner-design.md` §3).

The tree under test is **attacker-controlled** — freshly fetched from a public
registry — so most of these pin refusals rather than features: what the walk
must not follow, must not open, and must not silently omit.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from mcpwatchman.workers.scanner import inventory
from mcpwatchman.workers.scanner.inventory import (
    LARGE_FILE_BYTES,
    Inventory,
    Language,
    Role,
    enumerate_tree,
)


@pytest.fixture
def tree(tmp_path):
    """A small, realistic server tree."""
    (tmp_path / "index.js").write_text("console.log(1)")
    (tmp_path / "server.json").write_text('{"name":"x"}')
    (tmp_path / "README.md").write_text("# x")
    (tmp_path / "LICENSE").write_text("MIT")
    (tmp_path / "package.json").write_text('{"bin":{"srv":"index.js"},"main":"index.js"}')
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("assert 1")
    return tmp_path


# --- refusals: the tree is hostile ---------------------------------------


def test_symlinks_are_recorded_as_skipped_never_followed(tmp_path):
    """Following one reads the host filesystem. It is counted, not silently
    dropped — a silent skip is indistinguishable from an empty directory."""
    (tmp_path / "real.js").write_text("ok")
    (tmp_path / "escape").symlink_to("/etc/passwd")
    (tmp_path / "dir-escape").symlink_to("/etc")
    inv = enumerate_tree(tmp_path)
    assert [f.path for f in inv.files] == ["real.js"]
    assert inv.skipped.get("symlink") == 2


def test_non_regular_files_are_skipped_without_being_opened(tmp_path):
    """A FIFO blocks forever on open. `is_file()` is False for it, and that
    check must come before anything that reads."""
    (tmp_path / "real.js").write_text("ok")
    os.mkfifo(tmp_path / "pipe")
    inv = enumerate_tree(tmp_path)  # must return, not hang
    assert [f.path for f in inv.files] == ["real.js"]
    assert inv.skipped.get("not a regular file") == 1


def test_excluded_directories_are_omitted_but_not_counted_as_skipped(tmp_path):
    """Policy exclusion, not failure. Counting `node_modules` as 'skipped' would
    make a healthy tree look damaged in the report."""
    (tmp_path / "index.js").write_text("ok")
    for d in ("node_modules", ".git", "dist"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "junk.js").write_text("x" * 100)
    inv = enumerate_tree(tmp_path)
    assert [f.path for f in inv.files] == ["index.js"]
    assert inv.skipped == {}


def test_recorded_paths_are_relative_and_posix(tree):
    """An absolute path in the evidence trail leaks the worker's scratch layout
    and does not identify a file inside the artifact."""
    for f in enumerate_tree(tree).files:
        assert not f.path.startswith("/")
        assert "\\" not in f.path


def test_dotfiles_ARE_enumerated(tmp_path):
    """Pinned because it is the opposite of shell-glob behaviour and therefore
    easy to assume wrong: `Path.rglob('*')` includes hidden entries. Dotfiles
    are where CI workflows, `.npmrc` and the `.mcp.json` manifest live, so
    skipping them would blind several checks at once."""
    (tmp_path / ".mcp.json").write_text("{}")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "workflows").mkdir()
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("on: push")
    inv = enumerate_tree(tmp_path)
    paths = {f.path for f in inv.files}
    assert ".mcp.json" in paths
    assert ".github/workflows/ci.yml" in paths


# --- the MCP manifest -----------------------------------------------------


@pytest.mark.parametrize("name", ["server.json", "mcp.json", ".mcp.json"])
def test_the_mcp_manifest_is_found_under_each_conventional_name(tmp_path, name):
    """`04` §3 — the file saying what the server CLAIMS to do. auth_check and
    transparency_check both consume it."""
    (tmp_path / name).write_text('{"tools":[]}')
    inv = enumerate_tree(tmp_path)
    assert inv.mcp_manifest is not None
    assert inv.mcp_manifest.path == name
    assert inv.mcp_manifest.role is Role.MCP_MANIFEST


def test_absent_manifest_is_None_not_an_empty_record(tmp_path):
    (tmp_path / "index.js").write_text("ok")
    assert enumerate_tree(tmp_path).mcp_manifest is None


# --- entry points ---------------------------------------------------------


def test_entry_points_come_from_package_json_and_pyproject(tmp_path):
    (tmp_path / "package.json").write_text('{"bin":{"srv":"cli.js"},"main":"index.js"}')
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="1"\n[project.scripts]\nsrv="pkg.cli:main"\n'
    )
    eps = enumerate_tree(tmp_path).entry_points
    assert "cli.js" in eps and "index.js" in eps and "pkg.cli:main" in eps


@pytest.mark.parametrize(
    "content", ["not json at all", "[]", '{"bin": 42}', '{"bin": {"a": null}}', ""]
)
def test_a_malformed_package_json_yields_no_entry_points_and_does_not_raise(
    tmp_path, content
):
    """The manifest is attacker-controlled. Failing the scan over a malformed one
    would let any publisher stop themselves being scanned."""
    (tmp_path / "package.json").write_text(content)
    assert enumerate_tree(tmp_path).entry_points == ()


def test_a_malformed_pyproject_yields_no_entry_points_and_does_not_raise(tmp_path):
    (tmp_path / "pyproject.toml").write_text("this is not = valid toml [[[")
    assert enumerate_tree(tmp_path).entry_points == ()


def test_entry_points_are_deduplicated_in_declaration_order(tmp_path):
    (tmp_path / "package.json").write_text('{"bin":{"a":"x.js","b":"x.js"},"main":"x.js"}')
    assert enumerate_tree(tmp_path).entry_points == ("x.js",)


# --- language classification ---------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("a.py", Language.PYTHON), ("a.ts", Language.TYPESCRIPT),
        ("a.mjs", Language.JAVASCRIPT), ("a.go", Language.GO),
        ("a.rs", Language.RUST), ("a.yml", Language.YAML),
        ("a.toml", Language.TOML), ("Dockerfile", Language.DOCKERFILE),
        ("a.bin", Language.UNKNOWN),
    ],
)
def test_language_from_extension(tmp_path, name, expected):
    (tmp_path / name).write_text("x")
    assert enumerate_tree(tmp_path).files[0].language is expected


@pytest.mark.parametrize(
    "shebang,expected",
    [
        ("#!/usr/bin/env python3\n", Language.PYTHON),
        ("#!/bin/bash\n", Language.SHELL),
        ("#!/usr/bin/env node\n", Language.JAVASCRIPT),
        ("no shebang here\n", Language.UNKNOWN),
    ],
)
def test_extensionless_files_fall_back_to_the_shebang(tmp_path, shebang, expected):
    """`bin/server` with no extension is a real and common shape."""
    (tmp_path / "server").write_text(shebang + "print(1)")
    assert enumerate_tree(tmp_path).files[0].language is expected


# --- role classification --------------------------------------------------


def test_roles_are_assigned_from_name_and_location(tree):
    by_path = {f.path: f.role for f in enumerate_tree(tree).files}
    assert by_path["server.json"] is Role.MCP_MANIFEST
    assert by_path["package.json"] is Role.PACKAGE_MANIFEST
    assert by_path["package-lock.json"] is Role.LOCKFILE
    assert by_path["LICENSE"] is Role.LICENSE
    assert by_path["README.md"] is Role.DOCS
    assert by_path["src/app.py"] is Role.SOURCE
    assert by_path["tests/test_app.py"] is Role.TEST


def test_tests_are_separated_from_served_source(tmp_path):
    """`03` §3 grades what runs. A deliberately-unsafe fixture is evidence of
    testing, not of risk, so a finding there must not score like one in the
    served code."""
    (tmp_path / "app.py").write_text("x")
    (tmp_path / "test_app.py").write_text("x")
    (tmp_path / "a.test.ts").write_text("x")
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "thing.js").write_text("x")
    roles = {f.path: f.role for f in enumerate_tree(tmp_path).files}
    assert roles["app.py"] is Role.SOURCE
    assert roles["test_app.py"] is Role.TEST
    assert roles["a.test.ts"] is Role.TEST
    assert roles["spec/thing.js"] is Role.TEST


# --- size handling --------------------------------------------------------


def test_oversized_files_are_flagged_and_prefix_hashed(tmp_path):
    """`04` §3: flagged, not deeply inspected. The hash is then over a prefix,
    which the record says so a caller cannot mistake it for a whole-file digest."""
    big = tmp_path / "big.py"
    big.write_bytes(b"x" * (LARGE_FILE_BYTES + 5000))
    rec = enumerate_tree(tmp_path).files[0]
    assert rec.oversized and rec.size_bytes == LARGE_FILE_BYTES + 5000
    assert len(rec.sha256) == 64


def test_scannable_excludes_oversized_and_unclassifiable(tmp_path):
    (tmp_path / "ok.py").write_text("x")
    (tmp_path / "blob.bin").write_text("x")
    (tmp_path / "big.py").write_bytes(b"x" * (LARGE_FILE_BYTES + 1))
    inv = enumerate_tree(tmp_path)
    assert {f.path for f in inv.scannable} == {"ok.py"}
    assert len(inv.files) == 3  # all three are still recorded


def test_total_bytes_counts_every_recorded_file(tmp_path):
    (tmp_path / "a.py").write_bytes(b"x" * 10)
    (tmp_path / "b.py").write_bytes(b"x" * 20)
    assert enumerate_tree(tmp_path).total_bytes == 30


# --- query helpers --------------------------------------------------------


def test_by_language_and_by_role(tree):
    inv = enumerate_tree(tree)
    assert {f.path for f in inv.by_language(Language.PYTHON)} == {
        "src/app.py", "tests/test_app.py"
    }
    assert {f.path for f in inv.by_role(Role.DOCS)} == {"README.md"}


def test_an_empty_tree_is_empty_not_an_error(tmp_path):
    inv = enumerate_tree(tmp_path)
    assert inv == Inventory()


# ── v0.9.1 QA: the walk's bounds, and the manifest read's ────────────────────


def test_walk_does_not_descend_into_a_symlinked_directory(tmp_path: Path) -> None:
    """A symlink to a directory outside the tree must not be walked THROUGH.

    The old `rglob` form got this right by interpreter behaviour rather than by
    contract, and the interpreter CI runs (3.12) is not installable on the box
    this was written on. `os.walk(followlinks=False)` is a documented guarantee,
    so this test pins the property rather than the version.

    ⚠ NEGATIVE CONTROL: INCONCLUSIVE, not passing. Reverting to `sorted(rglob)`
    leaves this test green, because 3.14's `rglob` does not descend through a
    symlinked directory either. That is the whole reason the fix exists — the
    behaviour is correct on the interpreter we can measure and unverifiable on
    the one CI runs — so this is a contract pin, not a regression test, and must
    not be counted as evidence that the defect was reachable.
    """
    outside = tmp_path / "outside"
    (outside / "nested").mkdir(parents=True)
    (outside / "nested" / "host_secret.py").write_text("SECRET = 1")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.py").write_text("x = 1")
    (repo / "escape").symlink_to(outside)

    inv = enumerate_tree(repo)
    paths = {f.path for f in inv.files}

    assert paths == {"real.py"}
    assert not any("host_secret" in p for p in paths)
    assert inv.skipped.get("symlink") == 1


@contextlib.contextmanager
def _count_scandir():
    """Count `os.scandir` CALLS and the directory ENTRIES pulled off its iterator.

    ⚠ Two different bounds need two different counters, and an earlier version of
    this helper had only the first — which is why the `os.walk` form passed the
    cap test while still materialising a whole directory:

    * CALLS separate a streaming traversal from `sorted(rglob("*"))`, which
      scandirs every directory in the tree before the first cap check (measured:
      82 calls vs 8 over a 40-directory tree).
    * ENTRIES separate entry-by-entry consumption from `os.walk`, which builds a
      directory's complete listing before yielding it. Call counts cannot see
      that difference — one wide directory is one call either way.
    """
    counts = {"calls": 0, "entries": 0}
    real = os.scandir

    def counting(path="."):  # type: ignore[no-untyped-def]
        counts["calls"] += 1
        inner = real(path)

        class _Counting:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return inner.__exit__(*exc)

            def __iter__(self):
                return self

            def __next__(self):
                entry = next(inner)
                counts["entries"] += 1
                return entry

        return _Counting()

    with mock.patch.object(os, "scandir", counting):
        yield counts


def test_cap_stops_the_traversal_between_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`MAX_FILES` must stop the TRAVERSAL, not only truncate the record list.

    Negative control for `sorted(root.rglob("*"))`, which enumerates the whole
    tree before the first cap check can run.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(40):
        d = repo / f"d{i:02d}"
        d.mkdir()
        (d / "a.py").write_text("x = 1")

    monkeypatch.setattr(inventory, "MAX_FILES", 5)

    with _count_scandir() as counts:
        inv = enumerate_tree(repo)

    assert inv.truncated is True
    # Positive control: the instrument ran. Without it the assertion below also
    # passes on a probe that was never invoked — which is how the first version
    # of this test passed on the broken code.
    assert counts["calls"], "os.scandir was never called — the probe did not run"
    assert counts["calls"] < 20, (
        f"traversal did not stop at the cap: {counts['calls']} scandir calls over "
        f"a 40-directory tree (bounded is ~2, eager rglob is ~82)"
    )


def test_cap_stops_the_traversal_WITHIN_one_wide_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap must bite mid-directory, not only between directories.

    Negative control for `os.walk`, which materialises a directory's complete
    `filenames` list before yielding it — so one hostile directory holding
    millions of entries exhausts memory before any cap check is reached. The
    between-directories test above cannot detect this: one wide directory is a
    single `scandir` call either way.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(200):
        (repo / f"f{i:03d}.py").write_text("x = 1")

    monkeypatch.setattr(inventory, "MAX_FILES", 10)

    with _count_scandir() as counts:
        inv = enumerate_tree(repo)

    assert inv.truncated is True
    assert len(inv.files) == 10
    assert counts["entries"], "the scandir iterator was never advanced"
    assert counts["entries"] <= 15, (
        f"consumed {counts['entries']} of 200 entries at a cap of 10 — the "
        f"directory was materialised rather than streamed"
    )


def test_skipped_entries_advance_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entries the walk REJECTS still cost work, so they must count.

    Negative control for a cap keyed on `len(records)`: a repository of more
    than `MAX_FILES` symlinks or device nodes was traversed in full and then
    reported `truncated=False` — the bound both absent and denied.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(50):
        (repo / f"s{i:02d}.py").symlink_to("/nonexistent")
    (repo / "real.py").write_text("x = 1")

    monkeypatch.setattr(inventory, "MAX_FILES", 5)

    with _count_scandir() as counts:
        inv = enumerate_tree(repo)

    assert inv.truncated is True, "50 symlinks past a cap of 5 reported as complete"
    assert counts["entries"] <= 10, (
        f"walked {counts['entries']} entries at a cap of 5 — skipped entries did "
        f"not advance it"
    )


def test_excluded_directory_is_pruned_not_walked(tmp_path: Path) -> None:
    """An excluded directory must cost nothing, not be walked and then discarded."""
    repo = tmp_path / "repo"
    (repo / "node_modules" / "deep").mkdir(parents=True)
    for i in range(30):
        (repo / "node_modules" / "deep" / f"v{i}.js").write_text("x")
    (repo / "index.js").write_text("x")

    with _count_scandir() as counts:
        inv = enumerate_tree(repo)

    assert [f.path for f in inv.files] == ["index.js"]
    assert counts["calls"], "os.scandir was never called — the probe did not run"
    assert counts["calls"] == 1, (
        f"descended into an excluded directory: {counts['calls']} scandir calls"
    )


def test_ordering_is_by_path_component_not_by_string(tmp_path: Path) -> None:
    """`a/b.py` sorts before `a.py`, as path-component comparison gives.

    A plain string sort inverts this, because "/" (0x2f) > "." (0x2e). Pinned
    because the streaming walk has to restore an order the global `sorted()`
    used to provide for free.
    """
    repo = tmp_path / "repo"
    (repo / "a").mkdir(parents=True)
    (repo / "a" / "b.py").write_text("x = 1")
    (repo / "a.py").write_text("x = 1")

    inv = enumerate_tree(repo)
    assert [f.path for f in inv.files] == ["a/b.py", "a.py"]


def test_oversized_manifest_degrades_to_no_entry_points(tmp_path: Path) -> None:
    """A manifest past `MANIFEST_MAX_BYTES` is not read into memory.

    `source.py`'s archive caps allow a single member far larger than this, and
    these two files are the only ones parsed whole — so their size becomes
    resident memory where every other file's does not.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    padding = "A" * (inventory.MANIFEST_MAX_BYTES + 1024)
    (repo / "package.json").write_text(
        json.dumps({"bin": {"cli": "./cli.js"}, "_pad": padding})
    )

    inv = enumerate_tree(repo)
    assert inv.entry_points == ()

    # Positive control: the same manifest under the cap DOES yield the entry
    # point, so the test above is measuring the cap and not a broken parser.
    (repo / "package.json").write_text(json.dumps({"bin": {"cli": "./cli.js"}}))
    assert enumerate_tree(repo).entry_points == ("./cli.js",)


# ── Codex leg (v0.9.2): classification and manifest-parse defects ────────────


def test_malformed_pyproject_project_table_degrades(tmp_path: Path) -> None:
    """A syntactically VALID toml whose `project` is not a table must not crash.

    `data.get("project", {}).get("scripts", {})` raised AttributeError on
    `project = "invalid"` — an attacker-controlled manifest failing the whole
    scan, which is exactly what `_entry_points`' docstring promises cannot
    happen.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('project = "invalid"\n')

    inv = enumerate_tree(repo)  # must not raise
    assert inv.entry_points == ()

    # Positive control: a well-formed table still yields its scripts, so the
    # test above is measuring the guard and not a parser that stopped working.
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "x"\n[project.scripts]\nsrv = "pkg.mod:main"\n'
    )
    assert enumerate_tree(repo).entry_points == ("pkg.mod:main",)


def test_a_test_fixture_never_becomes_the_mcp_manifest(tmp_path: Path) -> None:
    """Location beats filename: `tests/fixtures/server.json` is TEST, not manifest.

    The filename roles used to be checked first, so a crafted fixture populated
    `Inventory.mcp_manifest` and the auth and transparency checks would have
    assessed it as the server's own declaration — inverting the separation
    `_role_of` exists to draw.
    """
    repo = tmp_path / "repo"
    (repo / "tests" / "fixtures").mkdir(parents=True)
    (repo / "tests" / "fixtures" / "server.json").write_text("{}")
    (repo / "app.py").write_text("x = 1")

    inv = enumerate_tree(repo)
    fixture = next(f for f in inv.files if f.path == "tests/fixtures/server.json")

    assert fixture.role is Role.TEST
    assert inv.mcp_manifest is None

    # Positive control: a REAL manifest at the root is still found.
    (repo / "server.json").write_text("{}")
    inv2 = enumerate_tree(repo)
    assert inv2.mcp_manifest is not None
    assert inv2.mcp_manifest.path == "server.json"


def test_a_lockfile_under_a_test_tree_is_test_not_lockfile(tmp_path: Path) -> None:
    """The same inversion reaches every filename role, not just the manifest."""
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "tests" / "package-lock.json").write_text("{}")
    (repo / "tests" / "README.md").write_text("# fixtures")

    roles = {f.path: f.role for f in enumerate_tree(repo).files}
    assert roles["tests/package-lock.json"] is Role.TEST
    assert roles["tests/README.md"] is Role.TEST


@pytest.mark.parametrize(
    "name",
    [
        "component.test.tsx",
        "widget.spec.jsx",
        "hook.test.mjs",
        "util.spec.cts",
        "legacy.test.js",
        "legacy.spec.ts",
    ],
)
def test_test_suffixes_cover_every_supported_js_variant(tmp_path: Path, name: str) -> None:
    """JSX and TSX test files were classified as served source.

    `component.test.tsx` does not end in `.test.ts`, so the hand-written suffix
    tuple missed every JSX/TSX variant — and a finding in a React test file
    would have scored as production risk. The tuple is now derived from the
    extension list so it cannot drift from it again.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / name).write_text("x")
    assert enumerate_tree(repo).files[0].role is Role.TEST
